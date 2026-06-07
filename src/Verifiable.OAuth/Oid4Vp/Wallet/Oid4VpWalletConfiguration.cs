using System.Buffers;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Oid4Vp;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Format-agnostic wallet configuration carrying the delegates an
/// <see cref="Oid4VpWalletClient"/> uses to parse the inbound JAR, encrypt the
/// response, and drive transport, plus the single presentation drop-out
/// (<see cref="ProduceVpTokenPresentations"/>) behind which the application
/// owns all credential-format logic.
/// </summary>
/// <remarks>
/// Bundles wallet plumbing in one record rather than fanning the delegates
/// across <see cref="Client.OAuthClientInfrastructure"/>. The wallet's surface stays
/// self-contained; the shared <see cref="Client.OAuthClientInfrastructure"/> exposes
/// only the flow-agnostic identifiers and transport delegates that every
/// client surface shares.
/// </remarks>
[DebuggerDisplay("Oid4VpWalletConfiguration")]
public sealed record Oid4VpWalletConfiguration
{
    /// <summary>
    /// The application's presentation drop-out. The wallet client invokes it
    /// after verifying the JAR, handing over the request-derived
    /// <see cref="Oid4VpPresentationContext"/>; the application runs the Core
    /// disclosure engine and the format primitives to produce the per-query
    /// presentations. See <see cref="ProduceVpTokenPresentationsDelegate"/>.
    /// </summary>
    public required ProduceVpTokenPresentationsDelegate ProduceVpTokenPresentations { get; init; }

    /// <summary>
    /// Resolves the Verifier's JAR signing public key by the <c>client_id</c>
    /// scheme prefix. The wallet client invokes this on every signed JAR — there
    /// is no pinned-key shortcut; a pre-registered/known key is expressed as a
    /// trivial resolver that returns that key. The deployment composes the slot
    /// from per-prefix handlers via
    /// <see cref="CompositeClientIdSigningKeyResolver"/>; the handlers read the
    /// current tenant's trust material off the threaded
    /// <see cref="Verifiable.Core.ExchangeContext"/>, so one stateless resolver
    /// serves every tenant. See <see cref="ResolveClientIdSigningKeyAsyncDelegate"/>.
    /// </summary>
    public required ResolveClientIdSigningKeyAsyncDelegate VerifierSigningKeyResolver { get; init; }

    /// <summary>
    /// The Wallet's declared capabilities, serialized into the
    /// <c>wallet_metadata</c> the Wallet POSTs on the OID4VP 1.0 §5.10
    /// <c>request_uri_method=post</c> path (see <see cref="Oid4VpWalletCapabilities"/>).
    /// A strict Verifier validates the full document, so this is what makes the
    /// §5.10 POST interoperable beyond the encryption JWKS.
    /// </summary>
    public required Oid4VpWalletCapabilities WalletCapabilities { get; init; }

    /// <summary>Base64url decoder used when parsing the JAR.</summary>
    public required DecodeDelegate Base64UrlDecoder { get; init; }

    /// <summary>Serialises a <see cref="JwtHeader"/> to UTF-8 JSON bytes for the JWE protected header.</summary>
    public required JwtHeaderSerializer JwtHeaderSerializer { get; init; }

    /// <summary>Serialises a <see cref="JwtPayload"/> to UTF-8 JSON bytes for <c>vp_token</c> assembly.</summary>
    public required JwtPayloadSerializer JwtPayloadSerializer { get; init; }

    /// <summary>Deserialises the JAR's protected header bytes into a dictionary.</summary>
    public required JarDictionaryDeserializer JarHeaderDeserializer { get; init; }

    /// <summary>Deserialises the JAR's payload bytes into a dictionary.</summary>
    public required JarDictionaryDeserializer JarPayloadDeserializer { get; init; }

    /// <summary>Deserialises the JAR's <c>dcql_query</c> claim from JSON.</summary>
    public required JarClaimDeserializer<DcqlQuery> DcqlQueryDeserializer { get; init; }

    /// <summary>Deserialises the JAR's <c>client_metadata</c> claim from JSON.</summary>
    public required JarClaimDeserializer<VerifierClientMetadata> ClientMetadataDeserializer { get; init; }

    /// <summary>Maps a key <see cref="Tag"/> to the JWK <c>crv</c> string for the JWE EPK header parameter.</summary>
    public required TagToEpkCrvDelegate TagToEpkCrvConverter { get; init; }

    /// <summary>ECDH-ES key agreement delegate for JWE encryption.</summary>
    public required KeyAgreementEncryptDelegate KeyAgreementEncrypt { get; init; }

    /// <summary>Concat KDF delegate per RFC 7518 §4.6.2.</summary>
    public required KeyDerivationDelegate KeyDerivation { get; init; }

    /// <summary>AES-GCM content encryption delegate for the JWE response.</summary>
    public required AeadEncryptDelegate AeadEncrypt { get; init; }

    /// <summary>
    /// Optional ECDH-ES key agreement decrypt delegate. Required only when the
    /// wallet client must accept a JWE-wrapped JAR per OID4VP 1.0 §5.10 — the
    /// Verifier-side encryption companion to the wallet's
    /// <see cref="KeyAgreementEncrypt"/> response path. <see langword="null"/>
    /// means JAR decryption is unsupported and an encrypted JAR will fail.
    /// </summary>
    public KeyAgreementDecryptDelegate? KeyAgreementDecrypt { get; init; }

    /// <summary>
    /// Optional AES-GCM content decryption delegate paired with
    /// <see cref="KeyAgreementDecrypt"/>. <see langword="null"/> means JAR
    /// decryption is unsupported.
    /// </summary>
    public AeadDecryptDelegate? AeadDecrypt { get; init; }

    /// <summary>
    /// Optional transport delegate the wallet client uses to drive the OID4VP
    /// 1.0 §5.10 <c>request_uri_method=post</c> path — POSTing
    /// <c>wallet_nonce</c> + <c>wallet_metadata</c> form fields to the
    /// Verifier's <c>request_uri</c> and reading the encrypted JAR back from
    /// the response body. <see langword="null"/> means the wallet client
    /// expects the caller to have fetched the JAR out-of-band and passed it
    /// via <see cref="PresentJarOptions.CompactJar"/>.
    /// </summary>
    public SendFormPostDelegate? SendFormPost { get; init; }

    /// <summary>Memory pool for transient cryptographic buffers.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }
}
