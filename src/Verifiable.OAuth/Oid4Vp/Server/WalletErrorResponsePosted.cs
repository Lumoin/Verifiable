using System;
using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Carries a Wallet's Authorization Error Response POSTed to the Verifier's response endpoint per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0
/// §8.2</see> — <c>error</c> (+ optional <c>error_description</c>) and <c>state</c> in place of
/// <c>response</c> or <c>vp_token</c>.
/// </summary>
/// <param name="Error">
/// The RFC 6749 §4.1.2.1 error code the Wallet reported (e.g. <c>access_denied</c> when the End-User
/// declined consent).
/// </param>
/// <param name="ErrorDescription">
/// The Wallet's optional human-readable error detail, or <see langword="null"/> when the Wallet omitted it.
/// </param>
/// <param name="ReceivedAt">The UTC instant the POST was received.</param>
/// <param name="RedirectUri">
/// The <c>redirect_uri</c> for same-device flows, read at <c>BuildInputAsync</c> time from the same
/// <c>ExchangeContext.Oid4VpRedirectUri</c> the verified state's <c>RedirectUri</c> is populated from.
/// <see langword="null"/> for cross-device flows.
/// </param>
[DebuggerDisplay("WalletErrorResponsePosted Error={Error} ReceivedAt={ReceivedAt}")]
public sealed record WalletErrorResponsePosted(
    string Error,
    string? ErrorDescription,
    DateTimeOffset ReceivedAt,
    Uri? RedirectUri): FlowInput;
