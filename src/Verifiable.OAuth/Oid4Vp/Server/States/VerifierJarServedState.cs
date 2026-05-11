using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Oid4Vp.Server.States;

/// <summary>
/// The signed JAR has been served to the Wallet at the per-flow JAR-fetch
/// endpoint. The Verifier is waiting for the Wallet to POST the encrypted
/// Authorization Response.
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

    /// <summary>
    /// The opaque per-flow token. Carried forward so the application's
    /// <see cref="Verifiable.OAuth.Server.AuthorizationServerIntegration.SaveFlowStateAsync"/>
    /// can index by it for the inbound direct_post lookup, and so terminal-state
    /// auditors can correlate flow records to wire-observable identifiers.
    /// </summary>
    public required string ParHandle { get; init; }

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

    /// <summary>
    /// The DCQL credential query identifier the Verifier set when constructing
    /// the JAR. Threaded forward so
    /// <see cref="VerifierResponseReceivedState.NextAction"/> can pass it into
    /// the <see cref="DecryptResponseAction"/> for response-side lookup against
    /// the JSON-encoded <c>vp_token</c>.
    /// </summary>
    public required CredentialQueryId CredentialQueryId { get; init; }
}
