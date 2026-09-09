using System;
using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Server.States;

/// <summary>
/// The Verifier successfully processed a Wallet's Authorization Error Response per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0
/// §8.2</see>. Terminal state: the direct_post endpoint answers this with HTTP 200, per §8.2's own MUST that
/// a successfully processed Authorization Response <em>or Authorization Error Response</em> gets a 200 JSON
/// answer.
/// </summary>
[DebuggerDisplay("VerifierWalletErrorReceived FlowId={FlowId} Error={Error}")]
public sealed record VerifierWalletErrorReceivedState: FlowState
{
    /// <summary>The RFC 6749 §4.1.2.1 error code the Wallet reported.</summary>
    public required string Error { get; init; }

    /// <summary>The Wallet's optional human-readable error detail, or <see langword="null"/>.</summary>
    public string? ErrorDescription { get; init; }

    /// <summary>The UTC instant the Wallet's Authorization Error Response was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }

    /// <summary>
    /// The <c>redirect_uri</c> the direct_post 200 response carries for same-device flows per OID4VP 1.0
    /// §8.2's MAY ("The Response URI MAY return the redirect_uri parameter in response to successful
    /// Authorization Responses or for Error Responses"). <see langword="null"/> for cross-device flows.
    /// </summary>
    public Uri? RedirectUri { get; init; }
}
