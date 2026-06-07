using System.Diagnostics;
using Verifiable.OAuth.Oid4Vp.Wallet.States;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// The outcome of a successful
/// <see cref="Oid4VpWalletClient.PresentJarAsync"/> call.
/// </summary>
/// <remarks>
/// <para>
/// The wallet client constructs the <c>vp_token</c> JSON and POSTs it to
/// <see cref="Oid4Vp.AuthorizationRequestObject.ResponseUri"/>. The wire
/// shape depends on the JAR's <c>response_mode</c>:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>direct_post.jwt</c> (HAIP 1.0 §5.1) — the wallet encrypts the
///     vp_token to the Verifier's advertised JWKS and POSTs the resulting
///     compact JWE in the <c>response</c> form field.
///   </description></item>
///   <item><description>
///     <c>direct_post</c> (OID4VP 1.0 §8.2 plaintext) — the wallet POSTs
///     the vp_token JSON verbatim in the <c>vp_token</c> form field.
///   </description></item>
/// </list>
/// <para>
/// The terminal PDA state on success is <see cref="ResponseSent"/>
/// (cross-device) or <see cref="BrowserRedirectIssued"/> (same-device when
/// the Verifier returned a redirect URI in its HTTP 200 body); only the
/// cross-device terminal is driven from inside
/// <see cref="Oid4VpWalletClient.PresentJarAsync"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("PresentationResult State={TerminalState.GetType().Name}")]
public sealed record PresentationResult
{
    /// <summary>
    /// The artifact the wallet client POSTed to <c>response_uri</c>. Either
    /// a compact JWE (for <c>response_mode=direct_post.jwt</c>) or the
    /// plaintext <c>vp_token</c> JSON object (for
    /// <c>response_mode=direct_post</c>). Retained for audit, replay
    /// testing, and end-to-end verification scenarios.
    /// </summary>
    public required string PostedResponseArtifact { get; init; }

    /// <summary>
    /// The terminal PDA state after the response was posted. For the cross-device
    /// flow this is always <see cref="ResponseSent"/>.
    /// </summary>
    public required OAuthFlowState TerminalState { get; init; }
}
