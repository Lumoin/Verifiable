using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Oid4Vp.Server.States;

/// <summary>
/// The signed JAR has been served to the Wallet at <c>GET /request/{requestUriToken}</c>.
/// The Verifier is waiting for the Wallet to POST the encrypted Authorization Response.
/// </summary>
/// <remarks>
/// Per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0 §5.4</see>,
/// signing and serving happen atomically in one HTTP request.
/// <see cref="OAuthFlowState.NextAction"/> returns
/// <see cref="Verifiable.Core.Automata.NullAction.Instance"/>.
/// Transitions to <see cref="VerifierResponseReceivedState"/> when the Wallet POSTs the
/// encrypted Authorization Response.
/// </remarks>
[DebuggerDisplay("VerifierJarServed FlowId={FlowId} ServedAt={ServedAt}")]
public sealed record VerifierJarServedState: OAuthFlowState
{
    /// <summary>The UTC instant at which the JAR was served to the Wallet.</summary>
    public required DateTimeOffset ServedAt { get; init; }

    /// <summary>Carried forward for KB-JWT nonce verification.</summary>
    public required TransactionNonce Nonce { get; init; }

    /// <summary>Carried forward for decryption at the direct_post endpoint.</summary>
    public required KeyId DecryptionKeyId { get; init; }

    /// <summary>
    /// Carried forward so <see cref="VerifierResponseReceivedState.NextAction"/> can
    /// produce a <see cref="DecryptResponseAction"/> with the correct allowed
    /// algorithm set.
    /// </summary>
    public required IReadOnlyList<string> AllowedEncAlgorithms { get; init; }
}
