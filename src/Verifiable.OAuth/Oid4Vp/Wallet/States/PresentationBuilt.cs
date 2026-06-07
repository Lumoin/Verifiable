using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Wallet.States;

/// <summary>
/// The VP token payload has been assembled and is ready for ECDH-ES encryption to the
/// Verifier's ephemeral public key.
/// </summary>
/// <remarks>
/// Transitions to <see cref="ResponseSent"/> after the encrypted JWE has been POSTed
/// to <see cref="AuthorizationRequestObject.ResponseUri"/>.
/// </remarks>
[DebuggerDisplay("PresentationBuilt FlowId={FlowId} ResponseUri={Request.ResponseUri}")]
public sealed record PresentationBuilt: OAuthFlowState
{
    /// <summary>
    /// The Authorization Request that must receive the response.
    /// Provides <c>response_uri</c>, nonce, and the Verifier's JWKS for encryption.
    /// </summary>
    public required AuthorizationRequestObject Request { get; init; }

    /// <summary>
    /// The VP token payload as UTF-8 JSON, ready to encrypt.
    /// Keyed by DCQL credential query identifier per OID4VP 1.0 §7.
    /// </summary>
    public required string VpTokenJson { get; init; }
}
