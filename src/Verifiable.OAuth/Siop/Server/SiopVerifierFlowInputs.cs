using Verifiable.JCose;

namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// The request-preparation input that initiates the SIOPv2 RP flow: the RP fixed the
/// <c>nonce</c>/<c>client_id</c> of a Self-Issued ID Token transaction and minted the per-flow
/// request handle.
/// </summary>
public sealed record SiopRequestPrepared: FlowInput
{
    /// <summary>The internal flow identifier.</summary>
    public required string FlowId { get; init; }

    /// <summary>The RP's <c>client_id</c> (the expected ID Token <c>aud</c>).</summary>
    public required string ClientId { get; init; }

    /// <summary>The transaction nonce the ID Token MUST echo.</summary>
    public required string Nonce { get; init; }

    /// <summary>The requested <c>id_token_type</c>, when constrained.</summary>
    public string? IdTokenType { get; init; }

    /// <summary>The accepted ID Token signing algorithms.</summary>
    public required IReadOnlyList<string> AllowedAlgorithms { get; init; }

    /// <summary>The opaque per-flow request handle.</summary>
    public required string RequestHandle { get; init; }

    /// <summary>The §9 Request Object signing key id, when by-reference.</summary>
    public string? SigningKeyId { get; init; }

    /// <summary>
    /// The decryption key id the Relying Party advertised the public half of as its encryption key.
    /// The Wallet encrypts the Self-Issued ID Token JWE to that public key; the response endpoint
    /// threads this through so the <see cref="DecryptSiopResponse"/> handler can resolve the private
    /// half via the server's <c>DecryptionKeyResolver</c>. <see langword="null"/> when the deployment
    /// does not advertise an encryption key (encrypted responses then fail closed).
    /// </summary>
    public string? DecryptionKeyId { get; init; }

    /// <summary>
    /// The content encryption algorithms the Relying Party advertises in its encryption metadata
    /// (the SIOP parallel of <c>encrypted_response_enc_values_supported</c>). The encrypted
    /// response's JWE <c>enc</c> header MUST be one of these values.
    /// </summary>
    public IReadOnlyList<string>? AllowedEncAlgorithms { get; init; }

    /// <summary>Whether the §9.1 Request Object <c>aud</c> is the static-discovery value.</summary>
    public bool UseStaticDiscoveryAudience { get; init; }

    /// <summary>
    /// Additional JOSE header claims to merge into the signed §9 Request Object header — the
    /// client-id-prefix material (<c>x5c</c>, <c>trust_chain</c>, <c>jwt</c>, <c>kid</c>) the wallet
    /// resolves the RP signing key from. <see langword="null"/> on the bespoke direct-key path. The
    /// SIOP parallel of the OID4VP JAR's additional header claims.
    /// </summary>
    public JwtHeader? RequestObjectAdditionalHeaderClaims { get; init; }

    /// <summary>When the transaction was prepared.</summary>
    public required DateTimeOffset PreparedAt { get; init; }

    /// <summary>When the transaction expires.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }
}


/// <summary>
/// The result of the §9 Request Object signing action, produced by the registered handler on the
/// <see cref="OAuthActionExecutor"/>. Advances the flow from <see cref="States.SiopRequestPreparedState"/>
/// to <see cref="States.SiopRequestObjectServedState"/> — the by-reference parallel of the OID4VP
/// <c>ServerJarSigned</c> input. The signed compact JWS itself rides the
/// <see cref="ExchangeContext"/> (the SIOP request-object slot), so the served state carries only
/// the transaction-forwarding values.
/// </summary>
public sealed record SiopRequestObjectSigned: FlowInput
{
    /// <summary>When the Request Object was signed and served.</summary>
    public required DateTimeOffset ServedAt { get; init; }
}


/// <summary>
/// The PURE input the response endpoint emits on receiving the Wallet's <c>id_token</c> POST —
/// it carries only the raw token. The cryptographic validation is deferred to the action the
/// resulting <see cref="States.SiopResponseReceivedState"/> declares, so the endpoint's
/// <c>BuildInputAsync</c> performs no side effects.
/// </summary>
public sealed record SiopResponsePosted: FlowInput
{
    /// <summary>The compact Self-Issued ID Token the Wallet POSTed.</summary>
    public required string IdToken { get; init; }

    /// <summary>When the POST was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }
}


/// <summary>
/// The PURE input the response endpoint emits on receiving an ENCRYPTED SIOPv2 Self-Issued ID Token
/// response — the Wallet returned the <c>id_token</c> as a compact JWE encrypted to the Relying
/// Party's public encryption key. It carries only the raw compact JWE; the JWE decryption, the
/// <c>enc</c> allow-list check, and the §11.1 validation are all deferred to the action the
/// resulting <see cref="States.SiopEncryptedResponseReceivedState"/> declares, so the endpoint's
/// <c>BuildInputAsync</c> performs no side effects. The encrypted sibling of
/// <see cref="SiopResponsePosted"/>, which carries the bare-JWS <c>id_token</c>.
/// </summary>
public sealed record SiopEncryptedResponsePosted: FlowInput
{
    /// <summary>The compact JWE (five dot-separated segments) carrying the encrypted Self-Issued ID Token.</summary>
    public required string EncryptedIdToken { get; init; }

    /// <summary>When the POST was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }
}


/// <summary>
/// The PURE input the response endpoint emits on receiving a SIOPv2 §12 combined response — the
/// Wallet POSTed BOTH an <c>id_token</c> (authenticating the End-User per §11.1) and a
/// <c>vp_token</c> (issuer-attested claims). It carries only the two raw artifacts; the §11.1
/// id_token validation, the <c>vp_token</c> presentation verification, and the §12 binding checks
/// are all deferred to the action the resulting <see cref="States.SiopCombinedResponseReceivedState"/>
/// declares, so the endpoint's <c>BuildInputAsync</c> performs no side effects.
/// </summary>
public sealed record SiopCombinedResponsePosted: FlowInput
{
    /// <summary>The compact Self-Issued ID Token the Wallet POSTed.</summary>
    public required string IdToken { get; init; }

    /// <summary>The <c>vp_token</c> presentation (SD-JWT VC + KB-JWT) the Wallet POSTed.</summary>
    public required string VpToken { get; init; }

    /// <summary>When the POST was received.</summary>
    public required DateTimeOffset ReceivedAt { get; init; }
}


/// <summary>
/// The result of the §11.1 validation action, produced by the registered handler on the
/// <see cref="OAuthActionExecutor"/>, driving the flow to terminal success.
/// </summary>
public sealed record SelfIssuedAuthenticationVerified: FlowInput
{
    /// <summary>The verified <c>sub</c>.</summary>
    public required string Subject { get; init; }

    /// <summary>The classified Subject Syntax Type of <see cref="Subject"/>.</summary>
    public required SiopSubjectSyntaxType SubjectSyntaxType { get; init; }

    /// <summary>The transaction nonce the verified token carried.</summary>
    public required string Nonce { get; init; }

    /// <summary>When verification completed.</summary>
    public required DateTimeOffset VerifiedAt { get; init; }
}


/// <summary>Drives any non-terminal SIOP RP flow state to terminal failure.</summary>
public sealed record SiopFlowFailed: FlowInput
{
    /// <summary>Why the flow failed.</summary>
    public required string Reason { get; init; }

    /// <summary>When the flow failed.</summary>
    public required DateTimeOffset FailedAt { get; init; }
}
