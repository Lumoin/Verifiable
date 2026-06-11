using System.Diagnostics;
using Verifiable.Core.Automata;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Siop.Server.States;

/// <summary>
/// The Wallet's SIOPv2 §12 combined response has been received and recorded against the transaction,
/// but not yet verified: one Authorization Response carrying BOTH a Self-Issued ID Token
/// (<c>id_token</c>) AND a Verifiable Presentation (<c>vp_token</c>). Overrides
/// <see cref="OAuthFlowState.NextAction"/> to declare a <see cref="ValidateCombinedSiopResponse"/>
/// action: the effectful §11.1 id_token validation, the <c>vp_token</c> presentation verification,
/// and the §12 binding checks run through the <see cref="OAuthActionExecutor"/> (not in the pure
/// transition), producing the <see cref="SelfIssuedAuthenticationVerified"/> /
/// <see cref="SiopFlowFailed"/> input that advances the flow. The combined-response sibling of
/// <see cref="SiopResponseReceivedState"/>, which carries only the id_token.
/// </summary>
[DebuggerDisplay("SiopCombinedResponseReceivedState FlowId={FlowId} ReceivedAt={ReceivedAt}")]
public sealed record SiopCombinedResponseReceivedState: OAuthFlowState
{
    /// <summary>The compact Self-Issued ID Token the Wallet POSTed. Preserved for audit and replay detection.</summary>
    public required string IdToken { get; init; }

    /// <summary>The <c>vp_token</c> presentation (SD-JWT VC + KB-JWT) the Wallet POSTed.</summary>
    public required string VpToken { get; init; }

    /// <summary>The RP's <c>client_id</c> — the required id_token <c>aud</c> and the vp_token KB-JWT <c>aud</c>.</summary>
    public required string ExpectedAudience { get; init; }

    /// <summary>The transaction nonce BOTH artifacts MUST echo (§12 binding).</summary>
    public required string ExpectedNonce { get; init; }

    /// <summary>The signing algorithms the RP accepts for the id_token.</summary>
    public required IReadOnlyList<string> AllowedAlgorithms { get; init; }

    /// <summary>When the POST was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }


    /// <inheritdoc/>
    public override PdaAction NextAction =>
        new ValidateCombinedSiopResponse(IdToken, VpToken, ExpectedAudience, ExpectedNonce, AllowedAlgorithms);
}
