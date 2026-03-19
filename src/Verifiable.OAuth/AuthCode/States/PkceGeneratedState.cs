using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.AuthCode.States;

/// <summary>
/// Initial flow state. PKCE parameters have been generated but no network call has been made.
/// </summary>
/// <remarks>Transitions to <see cref="ParRequestReadyState"/> when the PAR request body is composed.</remarks>
[DebuggerDisplay("PkceGenerated FlowId={FlowId}")]
public sealed record PkceGeneratedState: OAuthFlowState
{
    /// <summary>The PKCE verifier and challenge for this flow.</summary>
    public required PkceParameters Pkce { get; init; }

    /// <summary>
    /// The redirect URI for this flow instance. Exact-string-matched by the authorization
    /// server per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see>.
    /// </summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>The requested scopes.</summary>
    public required ImmutableArray<string> Scopes { get; init; }
}