using System;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core.Dcql;
using Verifiable.OAuth.Par;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.Oid4Vp.States;

/// <summary>
/// PAR has completed successfully. This is the first DB persistence point.
/// </summary>
/// <remarks>
/// <para>
/// The state persisted here is the authoritative snapshot for resuming the flow after a
/// process restart. All values needed for subsequent transitions — PKCE verifier, nonce,
/// DCQL query, and ephemeral encryption key — are carried forward from here.
/// </para>
/// <para>
/// Transitions to <see cref="JarReady"/> when the JAR JWT is signed.
/// </para>
/// <para>
/// This state owns the <see cref="Pkce"/> and <see cref="EncryptionKeyPair"/> and must
/// be disposed when superseded.
/// </para>
/// </remarks>
[DebuggerDisplay("ParCompleted FlowId={FlowId} RequestUri={Par.RequestUri}")]
public sealed record ParCompleted: OAuthFlowState, IDisposable
{
    private bool disposed;

    /// <summary>
    /// The PKCE parameters. The verifier is persisted here because it is needed at the
    /// token endpoint after a possible process restart. PKCE downgrade defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>
    /// requires confirming a <c>code_challenge</c> was present before accepting a
    /// <c>code_verifier</c> at the token endpoint.
    /// </summary>
    public required PkceParameters Pkce { get; init; }

    /// <summary>The redirect URI carried forward.</summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>The scopes carried forward.</summary>
    public required ImmutableArray<string> Scopes { get; init; }

    /// <summary>
    /// The PAR response. <see cref="ParResponse.RequestUri"/> is used as both the
    /// deep-link redirect parameter and the DB secondary lookup key.
    /// </summary>
    public required ParResponse Par { get; init; }

    /// <summary>
    /// The nonce bound to this transaction. Embedded in the JAR and verified in
    /// KB-JWTs returned in the authorization response.
    /// </summary>
    public required TransactionNonce Nonce { get; init; }

    /// <summary>
    /// The prepared DCQL query to embed in the JAR. Validation and coarse predicate
    /// extraction have already been performed by the caller.
    /// </summary>
    public required PreparedDcqlQuery Query { get; init; }

    /// <summary>
    /// The ephemeral ECDH key pair for encrypting the direct_post.jwt authorization response.
    /// The public key is included in the JAR; the private key is persisted here for
    /// post-restart decryption.
    /// </summary>
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
