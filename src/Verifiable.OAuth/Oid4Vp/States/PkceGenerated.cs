using System;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.Oid4Vp.States;

/// <summary>
/// Initial flow state. PKCE parameters have been generated but no network call has been made.
/// The verifier is live in memory; the challenge is ready to include in the PAR request body.
/// </summary>
/// <remarks>
/// Transitions to <see cref="ParRequestReady"/> when the PAR request body is composed.
/// This state owns the <see cref="Pkce"/> parameters and must be disposed when superseded.
/// </remarks>
[DebuggerDisplay("PkceGenerated FlowId={FlowId}")]
public sealed record PkceGenerated: OAuthFlowState, IDisposable
{
    private bool disposed;

    /// <summary>The PKCE verifier and challenge for this flow.</summary>
    public required PkceParameters Pkce { get; init; }

    /// <summary>
    /// The redirect URI for this flow instance. Exact-string-matched by the
    /// authorization server per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see>.
    /// </summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>The requested scopes (e.g., <c>openid</c>).</summary>
    public required ImmutableArray<string> Scopes { get; init; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Pkce.Dispose();
            disposed = true;
        }
    }
}
