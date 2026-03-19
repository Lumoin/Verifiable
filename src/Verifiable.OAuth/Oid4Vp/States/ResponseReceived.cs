using System;
using System.Diagnostics;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.Oid4Vp.States;

/// <summary>
/// The direct_post.jwt authorization response has been received. This is the second DB persistence point.
/// </summary>
/// <remarks>
/// <para>
/// The encrypted JWT body is retained verbatim for audit and replay testing.
/// Transitions to <see cref="PresentationVerified"/> after successful ECDH-ES decryption
/// and vp_token verification, or to <see cref="FlowFailed"/> on any error.
/// </para>
/// <para>
/// HAIP 1.0 requires the response to be encrypted to the verifier's ephemeral P-256 key
/// using ECDH-ES key agreement and A128GCM or A256GCM content encryption as defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6">RFC 7518 §4.6</see>.
/// </para>
/// <para>
/// This state owns the <see cref="Pkce"/> and <see cref="EncryptionKeyPair"/> and must be
/// disposed when superseded.
/// </para>
/// </remarks>
[DebuggerDisplay("ResponseReceived FlowId={FlowId} ReceivedAt={ReceivedAt}")]
public sealed record ResponseReceived: OAuthFlowState, IDisposable
{
    private bool disposed;

    /// <summary>
    /// The raw JWE compact serialization received from the HTTP POST.
    /// Preserved for audit and replay testing.
    /// </summary>
    public required string EncryptedResponseJwt { get; init; }

    /// <summary>The UTC instant at which the POST was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }

    /// <summary>The private key needed to decrypt <see cref="EncryptedResponseJwt"/>.</summary>
    public required EphemeralEncryptionKeyPair EncryptionKeyPair { get; init; }

    /// <summary>Carried forward for KB-JWT nonce verification.</summary>
    public required TransactionNonce Nonce { get; init; }

    /// <summary>
    /// Carried forward to support PKCE downgrade defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>.
    /// </summary>
    public required PkceParameters Pkce { get; init; }


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
