using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Siop.Server.States;

/// <summary>
/// The signed §9 Request Object has been served to the Wallet at the per-flow <c>request_uri</c>
/// endpoint. The Relying Party is waiting for the Wallet to POST the Self-Issued ID Token. The
/// by-reference parallel of the OID4VP verifier's
/// <see cref="Verifiable.OAuth.Oid4Vp.Server.States.VerifierJarServedState"/>.
/// </summary>
/// <remarks>
/// Per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-9">SIOPv2 §9</see>,
/// signing and serving happen atomically in one HTTP request: signing is an EFFECT run by the
/// <see cref="OAuthActionExecutor"/>, and the resulting <see cref="SiopRequestObjectSigned"/> input
/// steps the PDA here. The transaction-forwarding fields (<see cref="ClientId"/>, <see cref="Nonce"/>,
/// <see cref="AllowedAlgorithms"/>) are carried so the response endpoint can validate the Wallet's
/// <c>id_token</c> against the transaction exactly as it does from
/// <see cref="SiopRequestPreparedState"/> on the same-device (by-value) path.
/// </remarks>
[DebuggerDisplay("SiopRequestObjectServedState FlowId={FlowId} ClientId={ClientId} ServedAt={ServedAt}")]
public sealed record SiopRequestObjectServedState: FlowState
{
    /// <summary>The UTC instant at which the Request Object was served to the Wallet.</summary>
    public required DateTimeOffset ServedAt { get; init; }

    /// <summary>
    /// The opaque per-flow request handle. Carried forward so the application's
    /// <see cref="AuthorizationServerIntegration.SaveFlowStateAsync"/> can index by it for the
    /// inbound response lookup, and so terminal-state auditors can correlate flow records to the
    /// wire-observable <c>state</c> the Wallet echoes.
    /// </summary>
    public required string RequestHandle { get; init; }

    /// <summary>The RP's <c>client_id</c> — the required <c>aud</c> of the Self-Issued ID Token.</summary>
    public required string ClientId { get; init; }

    /// <summary>The transaction nonce the ID Token MUST echo.</summary>
    public required string Nonce { get; init; }

    /// <summary>The requested <c>id_token_type</c> (§7), when constrained.</summary>
    public string? IdTokenType { get; init; }

    /// <summary>The signing algorithms the RP accepts for the Self-Issued ID Token (alg allow-list; <c>none</c> is always rejected).</summary>
    public required IReadOnlyList<string> AllowedAlgorithms { get; init; }

    /// <summary>
    /// The decryption key id whose public half the Relying Party advertised as its encryption key.
    /// Carried forward so an encrypted Self-Issued ID Token response on the by-reference path can be
    /// decrypted exactly as on the by-value path; <see langword="null"/> when no encryption key is advertised.
    /// </summary>
    public string? DecryptionKeyId { get; init; }

    /// <summary>
    /// The content encryption algorithms the Relying Party advertises for an encrypted response. The
    /// JWE <c>enc</c> header is validated against this set before any cryptographic operation.
    /// </summary>
    public IReadOnlyList<string>? AllowedEncAlgorithms { get; init; }
}
