using System.Diagnostics;
using Verifiable.OAuth.Oid4Vp.Wallet.States;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// The outcome of a successful
/// <see cref="Oid4VpWalletClient{TCredential}.PresentJarAsync"/> call.
/// </summary>
/// <remarks>
/// The wallet client encrypts the constructed <c>vp_token</c> JSON to the
/// Verifier's advertised JWKS and POSTs the resulting compact JWE to
/// <see cref="Oid4Vp.AuthorizationRequestObject.ResponseUri"/>. The terminal
/// PDA state on success is <see cref="ResponseSent"/> (cross-device) or
/// <see cref="BrowserRedirectIssued"/> (same-device when the Verifier returned
/// a redirect URI in its HTTP 200 body); only the cross-device terminal is
/// driven from inside <see cref="Oid4VpWalletClient{TCredential}.PresentJarAsync"/>.
/// </remarks>
[DebuggerDisplay("PresentationResult State={TerminalState.GetType().Name}")]
public sealed record PresentationResult
{
    /// <summary>
    /// The compact JWE the wallet client POSTed to <c>response_uri</c>. Retained
    /// for audit, replay testing, and end-to-end verification scenarios.
    /// </summary>
    public required string EncryptedJweResponse { get; init; }

    /// <summary>
    /// The terminal PDA state after the response was posted. For the cross-device
    /// flow this is always <see cref="ResponseSent"/>.
    /// </summary>
    public required OAuthFlowState TerminalState { get; init; }
}
