using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Wallet.States;

/// <summary>
/// Terminal success state for the same-device flow. The Wallet has received a
/// <c>redirect_uri</c> from the Verifier's HTTP response and has issued the browser
/// redirect to return the user to the browser session.
/// </summary>
/// <remarks>
/// <para>
/// This state is only reached in the same-device flow. In the cross-device flow the
/// Wallet's presentation obligation ends at <see cref="ResponseSent"/> because no browser
/// session needs to be resumed. In the same-device flow the Verifier's HTTP 200 response
/// to the Wallet's <c>direct_post.jwt</c> POST contains a <c>redirect_uri</c> JSON field
/// per OID4VP 1.0 §8.2. The Wallet follows this URI to hand back control to the browser.
/// </para>
/// <para>
/// Both <see cref="ResponseSent"/> and <see cref="BrowserRedirectIssued"/> are accept
/// states — the application configures the accept predicate to match whichever terminal
/// state is expected for the flow variant being tested or deployed.
/// </para>
/// </remarks>
[DebuggerDisplay("BrowserRedirectIssued FlowId={FlowId} RedirectUri={RedirectUri}")]
public sealed record BrowserRedirectIssued: OAuthFlowState
{
    /// <summary>
    /// The URI the Wallet redirected the user's browser to, as provided in the Verifier's
    /// HTTP response body per OID4VP 1.0 §8.2.
    /// </summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>
    /// The opaque state value echoed from the Authorization Request, if present.
    /// Carried forward from <see cref="ResponseSent"/> for CSRF correlation.
    /// </summary>
    public required string? State { get; init; }

    /// <summary>The UTC instant at which the browser redirect was issued.</summary>
    public required DateTimeOffset RedirectIssuedAt { get; init; }
}
