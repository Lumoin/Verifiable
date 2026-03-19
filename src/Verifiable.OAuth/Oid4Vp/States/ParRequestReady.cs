using System;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.Oid4Vp.States;

/// <summary>
/// The PAR request body has been composed and is ready to POST to the authorization server.
/// </summary>
/// <remarks>
/// Transitions to <see cref="ParCompleted"/> when the PAR response is received.
/// This state owns the <see cref="Pkce"/> parameters and must be disposed when superseded.
/// </remarks>
[DebuggerDisplay("ParRequestReady FlowId={FlowId}")]
public sealed record ParRequestReady: OAuthFlowState, IDisposable
{
    private bool disposed;

    /// <summary>The PKCE parameters carried forward from <see cref="PkceGenerated"/>.</summary>
    public required PkceParameters Pkce { get; init; }

    /// <summary>The redirect URI carried forward.</summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>The scopes carried forward.</summary>
    public required ImmutableArray<string> Scopes { get; init; }

    /// <summary>
    /// The serialized PAR request body, ready to POST as
    /// <c>application/x-www-form-urlencoded</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 §2.1</see>.
    /// </summary>
    public required string EncodedBody { get; init; }


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
