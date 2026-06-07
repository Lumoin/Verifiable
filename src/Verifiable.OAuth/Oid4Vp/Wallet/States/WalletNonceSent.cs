using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Wallet.States;

/// <summary>
/// Intermediate Wallet flow state entered after the Wallet POSTs its
/// <c>wallet_nonce</c> (and optionally <c>wallet_metadata</c>) to the
/// Verifier's <c>request_uri</c> endpoint per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>.
/// Only reached on the <c>request_uri_method=post</c> path; the GET path goes
/// straight from <see cref="RequestUriReceived"/> to <see cref="JarParsed"/>.
/// </summary>
/// <remarks>
/// Carries the Wallet-issued nonce so that on transition to
/// <see cref="JarParsed"/> the Wallet can verify the JAR's <c>wallet_nonce</c>
/// claim echoes the value it sent — the replay defence the POST round-trip is
/// for.
/// </remarks>
[DebuggerDisplay("WalletNonceSent FlowId={FlowId} WalletNonce={WalletNonce}")]
public sealed record WalletNonceSent: OAuthFlowState
{
    /// <summary>
    /// The <c>request_uri</c> the Wallet POSTed to.
    /// </summary>
    public required Uri RequestUri { get; init; }

    /// <summary>
    /// The Wallet-issued nonce sent in the POST body. The JAR served in
    /// response MUST carry this value back in its <c>wallet_nonce</c> claim.
    /// </summary>
    public required string WalletNonce { get; init; }
}
