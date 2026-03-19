using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode.Server.States;

/// <summary>
/// The Authorization Server received and validated a Pushed Authorization Request.
/// A <c>request_uri</c> has been assigned and returned to the client. The server
/// is waiting for the authorization endpoint to be called.
/// </summary>
/// <remarks>
/// <para>
/// This is the first persistence point for the server-side flow. Everything needed
/// to validate the subsequent authorize and token requests is stored here:
/// the PKCE code challenge for downgrade defense, the redirect URI for exact-match
/// validation, and the scope for grant validation.
/// </para>
/// <para>
/// The <see cref="RequestUri"/> is used as a secondary lookup key when the
/// authorization endpoint receives <c>request_uri</c> as a query parameter. The
/// application maps <c>request_uri → flowId</c> to locate this state.
/// </para>
/// <para>
/// Transitions to <see cref="ServerCodeIssuedState"/> when <see cref="ServerAuthorizeCompleted"/>
/// arrives with a matching <see cref="RequestUri"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("ParRequestReceived FlowId={FlowId} RequestUri={RequestUri}")]
public sealed record ParRequestReceivedState: OAuthFlowState
{
    /// <summary>
    /// The <c>request_uri</c> assigned to this PAR entry and returned to the client.
    /// The application maps this to <see cref="OAuthFlowState.FlowId"/> so the
    /// authorization endpoint can load this state by <c>request_uri</c>.
    /// </summary>
    public required Uri RequestUri { get; init; }

    /// <summary>
    /// The PKCE S256 code challenge from the PAR request body.
    /// Stored so the token endpoint can verify <c>SHA256(code_verifier) == CodeChallenge</c>
    /// per <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>.
    /// </summary>
    public required string CodeChallenge { get; init; }

    /// <summary>
    /// The redirect URI from the PAR request. Exact-match validation is enforced
    /// at the authorization endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see>.
    /// </summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>The scope from the PAR request, carried forward for grant validation.</summary>
    public required string Scope { get; init; }

    /// <summary>
    /// The client identifier from the PAR request. Carried forward so the
    /// authorize and token endpoints can confirm the same client is continuing.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The <c>nonce</c> from the PAR request. Carried forward and bound into the
    /// ID Token at the token endpoint per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>.
    /// </summary>
    public required string Nonce { get; init; }
}
