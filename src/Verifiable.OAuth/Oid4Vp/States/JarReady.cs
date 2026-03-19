using System;
using System.Diagnostics;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.Oid4Vp.States;

/// <summary>
/// The JAR JWT has been signed and is ready to serve at the <c>request_uri</c> endpoint.
/// </summary>
/// <remarks>
/// Transitions to <see cref="JarServed"/> when the authorization request sender fetches the JAR.
/// The signed JWT is served with media type <c>application/oauth-authz-req+jwt</c> as required
/// by <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see>.
/// This state owns the <see cref="Jar"/>, <see cref="Pkce"/>, and <see cref="EncryptionKeyPair"/>
/// and must be disposed when superseded.
/// </remarks>
[DebuggerDisplay("JarReady FlowId={FlowId}")]
public sealed record JarReady: OAuthFlowState, IDisposable
{
    private bool disposed;

    /// <summary>
    /// The signed JAR, ready to serve as <c>application/oauth-authz-req+jwt</c>.
    /// Owned by this state.
    /// </summary>
    public required SignedJar Jar { get; init; }

    /// <summary>Carried forward from <see cref="ParCompleted"/>.</summary>
    public required PkceParameters Pkce { get; init; }

    /// <summary>Carried forward from <see cref="ParCompleted"/>.</summary>
    public required TransactionNonce Nonce { get; init; }

    /// <summary>Carried forward from <see cref="ParCompleted"/>.</summary>
    public required EphemeralEncryptionKeyPair EncryptionKeyPair { get; init; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Jar.Dispose();
            Pkce.Dispose();
            EncryptionKeyPair.Dispose();
            disposed = true;
        }
    }
}
