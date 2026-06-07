using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Wallet.States;

/// <summary>
/// Terminal success state. The encrypted Authorization Response has been POSTed to
/// the Verifier's <c>response_uri</c> and the server acknowledged receipt.
/// </summary>
/// <remarks>
/// The Wallet flow is complete. Any redirect URI returned in the server's response
/// body may be followed to complete the same-device flow, but that is outside the
/// scope of this PDA.
/// </remarks>
[DebuggerDisplay("ResponseSent FlowId={FlowId} ResponseUri={ResponseUri}")]
public sealed record ResponseSent: OAuthFlowState
{
    /// <summary>The <c>response_uri</c> to which the response was POSTed.</summary>
    public required Uri ResponseUri { get; init; }

    /// <summary>
    /// The opaque state value echoed from the Authorization Request, if present.
    /// Required for CSRF protection when the Verifier uses it per RFC 6749 §10.12.
    /// </summary>
    public required string? State { get; init; }

    /// <summary>The UTC instant at which the POST was acknowledged.</summary>
    public required DateTimeOffset SentAt { get; init; }
}
