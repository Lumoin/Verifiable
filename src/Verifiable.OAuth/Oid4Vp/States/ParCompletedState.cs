using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.Oid4Vp.States;

/// <summary>
/// PAR has completed successfully. This is the first DB persistence point.
/// </summary>
/// <remarks>
/// <para>
/// The state persisted here is the authoritative snapshot for resuming the flow after a
/// process restart. All values needed for subsequent transitions — PKCE verifier, nonce,
/// DCQL query, and the decryption key identifier — are carried forward from here.
/// </para>
/// <para>
/// Transitions to <see cref="JarReadyState"/> when the JAR JWT is signed.
/// </para>
/// </remarks>
[DebuggerDisplay("ParCompleted FlowId={FlowId} RequestUri={Par.RequestUri}")]
public sealed record ParCompletedState: OAuthFlowState
{
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
    /// The identifier of the ephemeral private key that will decrypt the
    /// <c>direct_post.jwt</c> response. The private scalar is held by the application's
    /// key store under this identifier. Carried forward through all states until
    /// <see cref="ResponseReceivedState"/> where the application resolves it back to live key
    /// material for decryption.
    /// </summary>
    public required KeyId DecryptionKeyId { get; init; }
}
