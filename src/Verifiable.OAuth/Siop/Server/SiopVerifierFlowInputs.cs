using Verifiable.Core.Dcql;
using Verifiable.Core.StatusList;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Server;

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

    /// <summary>
    /// The IETF Token Status List outcomes read for the SIOPv2 §12 combined response's <c>vp_token</c>,
    /// keyed by the DCQL credential query identifier it was presented under, or <see langword="null"/>
    /// when the response carried no <c>vp_token</c>, the presented credential carried no
    /// <c>status.status_list</c> reference, or the executor was registered without a
    /// <see cref="ResolveVerifiedStatusListTokenDelegate"/>. Read after the §12 seven-way id_token/vp_token
    /// binding has already been confirmed — Token Status List §8.3's "the validation procedures for the
    /// Referenced Token MUST precede any evaluation of a Referenced Token's status" ordering.
    /// </summary>
    public IReadOnlyDictionary<CredentialQueryId, CredentialStatusOutcome>? CredentialStatuses { get; init; }

    /// <summary>
    /// The SIOPv2 §12 combined response's verified <c>vp_token</c> credential, keyed by the
    /// <see cref="CredentialQueryId"/> it was presented under — parity with the OID4VP seat's own
    /// surfaced credentials — or <see langword="null"/> when the response carried no
    /// <c>vp_token</c>.
    /// </summary>
    public IReadOnlyDictionary<CredentialQueryId, VpCredentialClaims>? Credentials { get; init; }
}


/// <summary>Drives any non-terminal SIOP RP flow state to terminal failure.</summary>
public sealed record SiopFlowFailed: FlowInput
{
    /// <summary>Why the flow failed. Server-side logging only; never forwarded to the Wallet.</summary>
    public required string Reason { get; init; }

    /// <summary>When the flow failed.</summary>
    public required DateTimeOffset FailedAt { get; init; }

    /// <summary>
    /// The wire-safe refusal the response endpoint answers with, when the failure is one the endpoint
    /// can classify (a malformed or unverifiable response, an undeterminable credential status, or a
    /// relying-party policy refusal). <see langword="null"/> for a failure the endpoint has no typed
    /// cause for, which answers a genuine-fault 500 instead of a 400.
    /// </summary>
    /// <remarks>
    /// Carried (400): a replayed or over-length §11.2 nonce, a negative §11.1 validation verdict, a
    /// negative §12 id_token/vp_token binding conjunction, an encrypted response that is not a
    /// well-formed or size-bounded compact JWE, an unadvertised <c>enc</c>, an AES-GCM authentication-tag
    /// failure, an undeterminable credential status, and a relying-party policy refusal. Absent (500): no
    /// replay store configured under a <c>Required</c> policy, a combined response arriving without the
    /// vp_token-verification seams configured, no <see cref="AuthorizationServerCryptography.DecryptionKeyResolver"/>
    /// configured, or an advertised decryption key that does not resolve — every one a deployment
    /// configuration fault, not anything the Wallet did.
    /// </remarks>
    public VerifierFlowRefusal? Refusal { get; init; }

    /// <summary>
    /// The credential-status policy's typed refusal detail — which credential query, the raw status, its
    /// disposition — when <see cref="Refusal"/> carries <see cref="VerifierFlowRefusalKind.PolicyRefused"/>.
    /// <see langword="null"/> for every other refusal kind. Never rides the wire; <see cref="Reason"/> and
    /// this member are both server-side detail, kept off the generic <see cref="VerifierFlowRefusal.Description"/>
    /// per OID4VP 1.0 §15.9.
    /// </summary>
    public CredentialStatusRefusal? CredentialStatusRefusal { get; init; }
}
