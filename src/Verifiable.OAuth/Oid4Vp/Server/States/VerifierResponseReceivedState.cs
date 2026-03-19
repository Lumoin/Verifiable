using System.Diagnostics;
using Verifiable.Core.Automata;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Oid4Vp.Server.States;

/// <summary>
/// The encrypted <c>direct_post.jwt</c> Authorization Response has been received.
/// </summary>
/// <remarks>
/// Overrides <see cref="OAuthFlowState.NextAction"/> to produce a
/// <see cref="DecryptResponseAction"/>, driving the effectful dispatch loop to
/// decrypt the JWE — validating <c>enc</c> against <see cref="AllowedEncAlgorithms"/>
/// first — and verify the VP token before advancing to
/// <see cref="Verifiable.OAuth.Oid4Vp.States.PresentationVerifiedState"/>.
/// </remarks>
[DebuggerDisplay("VerifierResponseReceived FlowId={FlowId} ReceivedAt={ReceivedAt}")]
public sealed record VerifierResponseReceivedState: OAuthFlowState
{
    /// <summary>
    /// The raw JWE compact serialization from the HTTP POST body.
    /// Preserved for audit and replay detection.
    /// </summary>
    public required string EncryptedResponseJwt { get; init; }

    /// <summary>The UTC instant at which the POST was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }

    /// <summary>
    /// The identifier of the ephemeral private key used to decrypt
    /// <see cref="EncryptedResponseJwt"/>.
    /// </summary>
    public required KeyId DecryptionKeyId { get; init; }

    /// <summary>Carried forward for KB-JWT nonce verification.</summary>
    public required TransactionNonce Nonce { get; init; }

    /// <summary>
    /// The content encryption algorithms the Verifier advertised in
    /// <c>encrypted_response_enc_values_supported</c>. The JWE <c>enc</c> header is
    /// validated against this set before any cryptographic operation per
    /// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0 §5.1</see>.
    /// </summary>
    public required IReadOnlyList<string> AllowedEncAlgorithms { get; init; }

    /// <inheritdoc/>
    public override PdaAction NextAction =>
        new DecryptResponseAction(
            EncryptedResponseJwt,
            DecryptionKeyId,
            Nonce,
            AllowedEncAlgorithms);
}
