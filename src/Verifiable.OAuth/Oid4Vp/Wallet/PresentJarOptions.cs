using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Per-call inputs to <see cref="Oid4VpWalletClient.PresentJarAsync"/>. These
/// are the format-neutral request/transport inputs for a single presentation;
/// credential-format machinery (resolution, disclosure selection, presentation
/// building) lives behind <see cref="Oid4VpWalletConfiguration.ProduceVpTokenPresentations"/>.
/// </summary>
[DebuggerDisplay("PresentJarOptions")]
public sealed record PresentJarOptions
{
    /// <summary>
    /// The compact JAR received at the <c>request_uri</c>. When supplied,
    /// the wallet client skips the OID4VP 1.0 §5.10 POST step and parses
    /// this value directly. When <see langword="null"/>, the wallet client
    /// drives the §5.10 POST itself using
    /// <see cref="Oid4VpWalletConfiguration.SendFormPost"/> +
    /// <see cref="WalletExchangePublicKey"/> + <see cref="WalletExchangePrivateKey"/>.
    /// </summary>
    public string? CompactJar { get; init; }

    /// <summary>
    /// The <c>request_uri</c> the JAR was fetched from. Carried through the
    /// Wallet PDA's initial state for traceability and same-device redirect
    /// matching.
    /// </summary>
    public required Uri RequestUri { get; init; }

    /// <summary>
    /// The Verifier <c>client_id</c> the wallet expects to see in the JAR. Used
    /// for mix-up attack defence — the Wallet PDA rejects JARs whose
    /// <c>client_id</c> claim does not match. The wallet caller obtains this
    /// from the QR code or deep link payload alongside the <c>request_uri</c>.
    /// </summary>
    public required string ExpectedVerifierClientId { get; init; }

    /// <summary>
    /// Optional stable identifier for this presentation flow. When
    /// <see langword="null"/>, the wallet client generates a fresh GUID.
    /// </summary>
    /// <remarks>
    /// The holder/device signing key is NOT a per-call input — the application
    /// holds it (and its credentials and disclosure policy) behind
    /// <see cref="Oid4VpWalletConfiguration.ProduceVpTokenPresentations"/>.
    /// </remarks>
    public string? FlowId { get; init; }

    /// <summary>
    /// Optional ECDH-ES exchange private key used to decrypt a JWE-wrapped JAR
    /// per OID4VP 1.0 §5.10. The public side appears in <c>wallet_metadata.jwks</c>
    /// that the wallet POSTs to <c>request_uri_method=post</c>; the Verifier
    /// encrypts the signed JAR to that key. <see langword="null"/> means the
    /// wallet expects a plain signed JAR and an encrypted JAR will fail.
    /// </summary>
    /// <remarks>
    /// The wallet client also expects
    /// <see cref="Oid4VpWalletConfiguration.KeyAgreementDecrypt"/>
    /// and <see cref="Oid4VpWalletConfiguration.AeadDecrypt"/> to
    /// be configured when this property is set.
    /// </remarks>
    public PrivateKeyMemory? WalletExchangePrivateKey { get; init; }

    /// <summary>
    /// Optional ECDH-ES exchange public key the wallet advertises in
    /// <c>wallet_metadata.jwks</c> per OID4VP 1.0 §5.10. Required (together with
    /// <see cref="WalletExchangePrivateKey"/> and
    /// <see cref="Oid4VpWalletConfiguration.SendFormPost"/>) when
    /// <see cref="CompactJar"/> is <see langword="null"/> — i.e., when the
    /// wallet client drives the §5.10 POST itself.
    /// </summary>
    public PublicKeyMemory? WalletExchangePublicKey { get; init; }

    /// <summary>
    /// Optional content-encryption algorithm the wallet asks the Verifier to
    /// use when JWE-wrapping the JAR — emitted in
    /// <c>authorization_encrypted_response_enc</c> on the wallet_metadata POST
    /// body. <see langword="null"/> defers to
    /// <see cref="Verifiable.JCose.WellKnownJweEncryptionAlgorithms.A128Gcm"/>.
    /// </summary>
    public string? JarEncryptionEnc { get; init; }

    /// <summary>
    /// Optional inline Authorization Request parameters for OID4VP 1.0 §5.10
    /// deployments that send the request inline (no JAR, no request_uri).
    /// When non-<see langword="null"/>, the wallet client parses these as the
    /// Authorization Request, skipping JAR fetch and signature verification —
    /// the trust model is the <c>redirect_uri:</c> client identifier prefix
    /// per OID4VP 1.0 §5.9.3, where the Verifier's identity is its own
    /// response URI and authentication happens implicitly through the wallet
    /// POSTing the response back to that URI.
    /// </summary>
    /// <remarks>
    /// Required entries: <c>client_id</c>, <c>response_type</c>,
    /// <c>response_mode</c>, <c>response_uri</c>, <c>nonce</c>, <c>state</c>.
    /// Optional entries: <c>dcql_query</c> (JSON text), <c>client_metadata</c>
    /// (JSON text). The <c>client_id</c> MUST begin
    /// with the <c>redirect_uri:</c> prefix and the prefix's value MUST equal
    /// <c>response_uri</c> — the wallet enforces this.
    /// </remarks>
    public IReadOnlyDictionary<string, string>? InlineAuthorizationParameters { get; init; }

    /// <summary>
    /// Whether the Wallet requires the OAuth <c>state</c> parameter to be present on
    /// the parsed Authorization Request. OID4VP 1.0 §5 makes <c>state</c> OPTIONAL, so
    /// the default is <see cref="StateParameterPolicy.Optional"/> (spec-conformant — the
    /// Wallet accepts a request that omits it). A deployment sets
    /// <see cref="StateParameterPolicy.Required"/> when its own threat analysis wants the
    /// CSRF/replay binding an always-present <c>state</c> affords. Decided per call.
    /// </summary>
    public StateParameterPolicy StatePolicy { get; init; } = StateParameterPolicy.Optional;
}
