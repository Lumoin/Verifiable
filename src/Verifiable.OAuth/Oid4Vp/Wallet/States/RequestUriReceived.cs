using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Wallet.States;

/// <summary>
/// Initial Wallet flow state. A <c>request_uri</c> has been obtained — typically by
/// scanning a QR code or following a deep link — and the Wallet is ready to fetch
/// the JAR from it.
/// </summary>
/// <remarks>
/// Transitions to <see cref="JarParsed"/> after a successful HTTP GET to
/// <see cref="RequestUri"/> returns a valid <c>application/oauth-authz-req+jwt</c>
/// response.
/// </remarks>
[DebuggerDisplay("RequestUriReceived FlowId={FlowId} RequestUri={RequestUri}")]
public sealed record RequestUriReceived: OAuthFlowState
{
    /// <summary>
    /// The <c>request_uri</c> from which the JAR JWT must be fetched.
    /// Obtained from the QR code or deep-link payload.
    /// </summary>
    public required Uri RequestUri { get; init; }
}
