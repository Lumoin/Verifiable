using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The components needed to drive a DPoP-bound AuthCode flow against a test
/// host: the OAuth client wired with DPoP infrastructure, the matching
/// <see cref="ClientRegistration"/>, the generated DPoP key, the in-memory
/// nonce cache the client uses, and the underlying P-256 key material for
/// lifetime control.
/// </summary>
[DebuggerDisplay("DpopClientFixture")]
internal sealed class DpopClientFixture: IDisposable
{
    private bool disposed;


    public DpopClientFixture(
        OAuthClient client,
        ClientRegistration registration,
        DpopKey dpopKey,
        InMemoryDpopNonceCache nonceCache,
        PublicKeyMemory dpopPublicKey,
        PrivateKeyMemory dpopPrivateKey,
        Dictionary<string, FlowState> clientFlowStore)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(dpopKey);
        ArgumentNullException.ThrowIfNull(nonceCache);
        ArgumentNullException.ThrowIfNull(dpopPublicKey);
        ArgumentNullException.ThrowIfNull(dpopPrivateKey);
        ArgumentNullException.ThrowIfNull(clientFlowStore);

        Client = client;
        Registration = registration;
        DpopKey = dpopKey;
        NonceCache = nonceCache;
        DpopPublicKey = dpopPublicKey;
        DpopPrivateKey = dpopPrivateKey;
        ClientFlowStore = clientFlowStore;
    }


    /// <summary>The OAuth client wired with DPoP infrastructure.</summary>
    public OAuthClient Client { get; }

    /// <summary>The matching client registration.</summary>
    public ClientRegistration Registration { get; }

    /// <summary>The DPoP signing key used for proof construction.</summary>
    public DpopKey DpopKey { get; }

    /// <summary>The nonce cache the client retries against.</summary>
    public InMemoryDpopNonceCache NonceCache { get; }

    /// <summary>The DPoP public key material.</summary>
    public PublicKeyMemory DpopPublicKey { get; }

    /// <summary>The DPoP private key material.</summary>
    public PrivateKeyMemory DpopPrivateKey { get; }

    /// <summary>
    /// The client-side flow-state store. Exposed so tests can read back the
    /// flow identifier (which the client treats as <c>state</c>) without
    /// reaching into the infrastructure delegate closures.
    /// </summary>
    public Dictionary<string, FlowState> ClientFlowStore { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        DpopPublicKey.Dispose();
        DpopPrivateKey.Dispose();
    }
}
