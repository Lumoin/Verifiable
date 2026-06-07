using System.Diagnostics;
using Verifiable.Core.Automata;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Server.States;

/// <summary>
/// Intermediate Verifier flow state entered after the Wallet POSTs to the
/// <c>request_uri</c> endpoint with <c>wallet_nonce</c> (and optionally
/// <c>wallet_metadata</c>) per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>.
/// Only reached on the <c>request_uri_method=post</c> path; the GET path
/// transitions directly from <see cref="VerifierParReceivedState"/> to
/// <see cref="VerifierJarServedState"/>.
/// </summary>
/// <remarks>
/// Carries everything <see cref="VerifierParReceivedState"/> carried (so the
/// JAR-signing action has the same inputs available) plus the
/// <see cref="WalletNonce"/> the Wallet sent, which the JAR-signing handler
/// echoes as the JAR's <c>wallet_nonce</c> claim. <see cref="OAuthFlowState.NextAction"/>
/// returns <see cref="Verifiable.Core.Automata.NullAction.Instance"/> — JAR
/// signing is dispatched by the endpoint handler, not auto-produced.
/// </remarks>
[DebuggerDisplay("VerifierWalletPostReceived FlowId={FlowId} WalletNonce={WalletNonce}")]
public sealed record VerifierWalletPostReceivedState: OAuthFlowState
{
    /// <summary>The PAR response carrying <c>request_uri</c> and <c>expires_in</c>.</summary>
    public required ParResponse Par { get; init; }

    /// <summary>The opaque per-flow token, threaded forward to the JAR's <c>state</c> claim.</summary>
    public required string ParHandle { get; init; }

    /// <summary>The transaction nonce to embed in the JAR.</summary>
    public required TransactionNonce Nonce { get; init; }

    /// <summary>The prepared DCQL query to embed in the JAR.</summary>
    public required PreparedDcqlQuery Query { get; init; }

    /// <summary>The identifier of the ephemeral private key for JWE decryption.</summary>
    public required KeyId DecryptionKeyId { get; init; }

    /// <summary>The identifier of the JAR signing key.</summary>
    public required KeyId SigningKeyId { get; init; }

    /// <summary>The Verifier-advertised content encryption algorithms.</summary>
    public required IReadOnlyList<string> AllowedEncAlgorithms { get; init; }

    /// <summary>
    /// The fresh nonce the Wallet sent in the POST body. The JAR-signing handler
    /// MUST echo this value as the <c>wallet_nonce</c> claim in the signed JAR
    /// per OID4VP 1.0 §5.10; the Wallet rejects the JAR otherwise.
    /// </summary>
    public required string WalletNonce { get; init; }

    /// <summary>
    /// The raw <c>wallet_metadata</c> JSON the Wallet sent in the POST body, when
    /// present. The Verifier MAY use this to tailor the JAR's <c>client_metadata</c>
    /// (algorithm sets, formats). <see langword="null"/> when the Wallet sent no
    /// metadata.
    /// </summary>
    public string? WalletMetadataJson { get; init; }

    /// <summary>
    /// The JSON text of the <c>jwks</c> sub-object of <c>wallet_metadata</c>
    /// (braces included), extracted on transition from
    /// <see cref="WalletMetadataJson"/>. Carries the Wallet's encryption
    /// JWKS forward to the JAR-signing action so the signed JWS is
    /// JWE-wrapped to the Wallet's public exchange key per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>.
    /// <see langword="null"/> when the Wallet's metadata carried no <c>jwks</c>.
    /// </summary>
    public string? WalletEncryptionJwksJson { get; init; }

    /// <summary>
    /// The content-encryption algorithm (JWA <c>enc</c>) the Wallet advertised
    /// via <c>authorization_encrypted_response_enc</c> on its wallet_metadata.
    /// Threaded onto <see cref="SignJarAction.JarEncryptionEnc"/>; ignored
    /// when <see cref="WalletEncryptionJwksJson"/> is <see langword="null"/>.
    /// </summary>
    public string? JarEncryptionEnc { get; init; }

    /// <summary>
    /// Optional <c>transaction_data</c> descriptors carried through from
    /// <see cref="VerifierParReceivedState"/> per OID4VP 1.0 §8.4.
    /// </summary>
    public IReadOnlyList<string>? TransactionData { get; init; }

    /// <summary>
    /// Optional additional JOSE header claims carried through from
    /// <see cref="VerifierParReceivedState"/> per OID4VP 1.0 §5.9.3.
    /// </summary>
    public JwtHeader? JarAdditionalHeaderClaims { get; init; }


    /// <inheritdoc/>
    public override PdaAction NextAction =>
        new SignJarAction(
            ParHandle,
            Nonce,
            Query,
            SigningKeyId,
            WalletNonce,
            TransactionData,
            JarAdditionalHeaderClaims,
            ResponseMode: null,
            WalletEncryptionJwksJson: WalletEncryptionJwksJson,
            JarEncryptionEnc: JarEncryptionEnc);
}
