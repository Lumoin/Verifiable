using System.Diagnostics;
using Verifiable.Core.Automata;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Siop.Server.States;

/// <summary>
/// The Wallet's Self-Issued ID Token has been received and recorded against the transaction, but
/// not yet verified. Overrides <see cref="OAuthFlowState.NextAction"/> to declare a
/// <see cref="ValidateSelfIssuedIdToken"/> action: the effectful §11.1 validation runs through the
/// <see cref="OAuthActionExecutor"/> (not in the pure transition), producing the
/// <see cref="SelfIssuedAuthenticationVerified"/> / <see cref="SiopFlowFailed"/> input that
/// advances the flow. This durable received-but-unverified checkpoint mirrors the OID4VP
/// verifier's response-received state.
/// </summary>
[DebuggerDisplay("SiopResponseReceivedState FlowId={FlowId} ReceivedAt={ReceivedAt}")]
public sealed record SiopResponseReceivedState: OAuthFlowState
{
    /// <summary>The compact Self-Issued ID Token the Wallet POSTed. Preserved for audit and replay detection.</summary>
    public required string IdToken { get; init; }

    /// <summary>The RP's <c>client_id</c> — the required <c>aud</c> of the token.</summary>
    public required string ExpectedAudience { get; init; }

    /// <summary>The transaction nonce the token MUST echo.</summary>
    public required string ExpectedNonce { get; init; }

    /// <summary>The signing algorithms the RP accepts for the token.</summary>
    public required IReadOnlyList<string> AllowedAlgorithms { get; init; }

    /// <summary>When the POST was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }


    /// <inheritdoc/>
    public override PdaAction NextAction =>
        new ValidateSelfIssuedIdToken(IdToken, ExpectedAudience, ExpectedNonce, AllowedAlgorithms);
}
