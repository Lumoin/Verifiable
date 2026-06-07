using System.Diagnostics;
using Verifiable.Core.Automata;

using Verifiable.Core.Model.Dcql;

namespace Verifiable.OAuth.Oid4Vp.Server.States;

/// <summary>
/// The unencrypted <c>direct_post</c> Authorization Response has been
/// received. Sibling to <see cref="VerifierResponseReceivedState"/>
/// (which carries the encrypted <c>direct_post.jwt</c> JWE); produced when
/// the JAR's <c>response_mode</c> is <c>direct_post</c> per OID4VP 1.0 §8.2.
/// </summary>
/// <remarks>
/// Overrides <see cref="OAuthFlowState.NextAction"/> to produce a
/// <see cref="ProcessVpTokenAction"/>, driving the effectful dispatch loop
/// to verify the VP token (no decryption — the JSON is already in plaintext)
/// before advancing to
/// <see cref="Verifiable.OAuth.Oid4Vp.States.PresentationVerifiedState"/>.
/// </remarks>
[DebuggerDisplay("VerifierUnencryptedResponseReceived FlowId={FlowId} ReceivedAt={ReceivedAt}")]
public sealed record VerifierUnencryptedResponseReceivedState: OAuthFlowState
{
    /// <summary>
    /// The plaintext <c>vp_token</c> JSON string. Preserved for audit and
    /// replay detection.
    /// </summary>
    public required string VpTokenJson { get; init; }

    /// <summary>The UTC instant at which the POST was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }

    /// <summary>Carried forward for KB-JWT nonce verification.</summary>
    public required TransactionNonce Nonce { get; init; }

    /// <summary>
    /// The DCQL credential query identifiers the Verifier set in its JAR.
    /// The <see cref="ProcessVpTokenAction"/> handler uses each as a lookup
    /// key against the parsed <c>vp_token</c> JSON object per OID4VP 1.0
    /// §8.1.
    /// </summary>
    public required IReadOnlyList<CredentialQuery> CredentialQueries { get; init; }

    /// <summary>
    /// The <c>transaction_data</c> descriptors the Verifier bound into the
    /// JAR per OID4VP 1.0 §8.4, threaded forward so the
    /// <see cref="ProcessVpTokenAction"/> handler can validate the Wallet's
    /// echoed hashes.
    /// </summary>
    public IReadOnlyList<string>? TransactionData { get; init; }

    /// <inheritdoc/>
    public override PdaAction NextAction =>
        new ProcessVpTokenAction(
            VpTokenJson,
            Nonce,
            CredentialQueries,
            TransactionData);
}
