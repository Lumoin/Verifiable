using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Server-side input produced by the <c>request_uri</c> endpoint when the
/// Wallet POSTs <c>wallet_nonce</c> (and optionally <c>wallet_metadata</c>)
/// per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>.
/// Drives <see cref="States.VerifierParReceivedState"/> →
/// <see cref="States.VerifierWalletPostReceivedState"/>.
/// </summary>
/// <param name="WalletNonce">
/// The <c>wallet_nonce</c> form-body parameter the Wallet sent — to be echoed
/// in the JAR's <c>wallet_nonce</c> claim by the JAR-signing handler.
/// </param>
/// <param name="WalletMetadataJson">
/// The raw <c>wallet_metadata</c> JSON the Wallet sent, when present;
/// <see langword="null"/> otherwise.
/// </param>
/// <param name="ReceivedAt">The UTC instant at which the POST was received.</param>
[DebuggerDisplay("ServerWalletPostReceived WalletNonce={WalletNonce}")]
public sealed record ServerWalletPostReceived(
    string WalletNonce,
    string? WalletMetadataJson,
    DateTimeOffset ReceivedAt): OAuthFlowInput;
