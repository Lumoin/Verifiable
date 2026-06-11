using System.Diagnostics;
using Verifiable.JCose;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Siop.Server.States;

/// <summary>
/// The SIOPv2 RP transaction after request preparation: the Relying Party has fixed the
/// <c>nonce</c> and <c>client_id</c> (audience) it will bind a Self-Issued ID Token to and
/// minted the per-flow request handle. The response endpoint loads this state to validate the
/// Wallet's <c>id_token</c> against the transaction.
/// </summary>
[DebuggerDisplay("SiopRequestPreparedState FlowId={FlowId} ClientId={ClientId} Nonce={Nonce}")]
public sealed record SiopRequestPreparedState: OAuthFlowState
{
    /// <summary>The RP's <c>client_id</c> — the expected <c>aud</c> of the Self-Issued ID Token.</summary>
    public required string ClientId { get; init; }

    /// <summary>The transaction nonce the ID Token MUST echo (§9 REQUIRED).</summary>
    public required string Nonce { get; init; }

    /// <summary>The requested <c>id_token_type</c> (§7), when constrained.</summary>
    public string? IdTokenType { get; init; }

    /// <summary>The signing algorithms the RP accepts for the ID Token (alg allow-list; <c>none</c> is always rejected).</summary>
    public required IReadOnlyList<string> AllowedAlgorithms { get; init; }

    /// <summary>The opaque per-flow handle carried in the <c>request_uri</c> and echoed as <c>state</c>.</summary>
    public required string RequestHandle { get; init; }

    /// <summary>The key id used to sign the §9 Request Object served at the <c>request_uri</c>, when by-reference.</summary>
    public string? SigningKeyId { get; init; }

    /// <summary>
    /// The decryption key id whose public half the Relying Party advertised as its encryption key.
    /// Threaded forward so an encrypted Self-Issued ID Token response can be decrypted; <see langword="null"/>
    /// when the deployment advertises no encryption key.
    /// </summary>
    public string? DecryptionKeyId { get; init; }

    /// <summary>
    /// The content encryption algorithms the Relying Party advertises for an encrypted response. The
    /// JWE <c>enc</c> header is validated against this set before any cryptographic operation.
    /// </summary>
    public IReadOnlyList<string>? AllowedEncAlgorithms { get; init; }

    /// <summary>
    /// Whether the §9.1 Request Object <c>aud</c> is the static-discovery value
    /// (<c>https://self-issued.me/v2</c>) rather than the dynamically discovered issuer.
    /// </summary>
    public bool UseStaticDiscoveryAudience { get; init; }

    /// <summary>
    /// Additional JOSE header claims to merge into the signed §9 Request Object header — the
    /// client-id-prefix material (<c>x5c</c>, <c>trust_chain</c>, <c>jwt</c>, <c>kid</c>) the wallet
    /// resolves the RP signing key from. Carried so the request-object endpoint can hand it to the
    /// <see cref="SignSiopRequestObject"/> action. <see langword="null"/> on the bespoke direct-key path.
    /// </summary>
    public JwtHeader? RequestObjectAdditionalHeaderClaims { get; init; }
}
