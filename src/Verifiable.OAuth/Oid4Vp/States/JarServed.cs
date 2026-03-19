using System;
using System.Diagnostics;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.Oid4Vp.States;

/// <summary>
/// The JAR has been fetched. The flow is waiting for the direct_post.jwt authorization response.
/// </summary>
/// <remarks>
/// Transitions to <see cref="ResponseReceived"/> when the authorization response is posted.
/// This state owns the <see cref="Pkce"/> and <see cref="EncryptionKeyPair"/> and must be
/// disposed when superseded.
/// </remarks>
[DebuggerDisplay("JarServed FlowId={FlowId} FetchedAt={FetchedAt}")]
public sealed record JarServed: OAuthFlowState, IDisposable
{
    private bool disposed;

    /// <summary>The UTC instant at which the JAR was first fetched.</summary>
    public required DateTimeOffset FetchedAt { get; init; }

    /// <summary>Carried forward from <see cref="JarReady"/>.</summary>
    public required PkceParameters Pkce { get; init; }

    /// <summary>Carried forward from <see cref="JarReady"/>.</summary>
    public required TransactionNonce Nonce { get; init; }

    /// <summary>Carried forward from <see cref="JarReady"/>.</summary>
    public required EphemeralEncryptionKeyPair EncryptionKeyPair { get; init; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Pkce.Dispose();
            EncryptionKeyPair.Dispose();
            disposed = true;
        }
    }
}
