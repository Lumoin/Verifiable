using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;

namespace Verifiable.OAuth.Oid4Vci.Wallet;

/// <summary>
/// POSTs an <c>application/x-www-form-urlencoded</c> body to
/// <paramref name="endpoint"/> and returns the full HTTP response. Used by
/// <see cref="Oid4VciWalletClient"/> for the §6 Pre-Authorized Code Token
/// Request — carrying a <c>DPoP</c> proof header in <paramref name="headers"/>
/// when the request is sender-constrained (RFC 9449 §5: "all access token
/// requests regardless of grant type"). Transport-agnostic: the application
/// supplies an implementation (HttpClient-backed in deployments,
/// Kestrel-loopback in tests); the library composes no <c>System.Net</c>
/// types.
/// </summary>
/// <remarks>
/// <paramref name="endpoint"/> is issuer-named — read out of discovered §12.2 Credential Issuer
/// Metadata or Authorization Server Metadata, not chosen by this library — and may share an
/// origin with the application's own backend. A browser host therefore sends every request this
/// implementation builds with credentials omitted (<c>BrowserRequestCredentials.Omit</c> on the
/// request, in the application's own transport), because the Fetch Standard's default credentials
/// mode is <c>same-origin</c>: "A request has an associated credentials mode, which is 'omit',
/// 'same-origin', or 'include'. Unless stated otherwise, it is 'same-origin'." The library places
/// no origin restriction on <paramref name="endpoint"/> and evaluates only <paramref name="context"/>'s
/// <see cref="Verifiable.Core.OutboundFetch.OutboundFetchPolicy"/>.
/// </remarks>
/// <param name="endpoint">The token endpoint URL.</param>
/// <param name="formFields">The form fields to URL-encode into the request body.</param>
/// <param name="headers">
/// Composed request headers — empty for a plain Pre-Authorized Code Token Request, carrying a
/// <c>DPoP</c> proof when the request is sender-constrained. The library attaches the header
/// here rather than the transport composing it, so the transport stays authentication-scheme-naive.
/// </param>
/// <param name="context">The per-operation exchange context carrying the outbound-fetch policy the Wallet evaluates before dialing.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The HTTP response carrying status code, body, and response headers.</returns>
public delegate ValueTask<HttpResponseData> Oid4VciFormPostDelegate(
    Uri endpoint,
    IReadOnlyDictionary<string, string> formFields,
    OutgoingHeaders headers,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// POSTs a JSON body to <paramref name="endpoint"/> with the supplied request
/// headers and returns the full HTTP response. Used by
/// <see cref="Oid4VciWalletClient"/> for the §7 Nonce Request, the §8
/// Credential Request, the §9 Deferred Credential Request, and the §11
/// Notification Request — the headers carry the <c>Authorization</c> (and,
/// when DPoP-bound, <c>DPoP</c>) values the client composes, and the response
/// carries the <c>DPoP-Nonce</c> / <c>WWW-Authenticate</c> headers a
/// <c>use_dpop_nonce</c> challenge answers with (RFC 9449 §9). Transport-agnostic:
/// no <c>System.Net</c> in the library.
/// </summary>
/// <remarks>
/// <paramref name="endpoint"/> is issuer-named — read out of discovered §12.2 Credential Issuer
/// Metadata, not chosen by this library — and may share an origin with the application's own
/// backend. A browser host therefore sends every request this implementation builds with
/// credentials omitted (<c>BrowserRequestCredentials.Omit</c> on the request, in the
/// application's own transport), because the Fetch Standard's default credentials mode is
/// <c>same-origin</c>: "A request has an associated credentials mode, which is 'omit',
/// 'same-origin', or 'include'. Unless stated otherwise, it is 'same-origin'." The library places
/// no origin restriction on <paramref name="endpoint"/> and evaluates only <paramref name="context"/>'s
/// <see cref="Verifiable.Core.OutboundFetch.OutboundFetchPolicy"/>.
/// </remarks>
/// <param name="endpoint">The endpoint URL.</param>
/// <param name="jsonBody">The JSON request body. Empty for the §7 Nonce Request, which carries no body.</param>
/// <param name="headers">The request headers the client composed.</param>
/// <param name="context">The per-operation exchange context carrying the outbound-fetch policy the Wallet evaluates before dialing.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The HTTP response carrying status code, body, and response headers (including <c>Content-Type</c>).</returns>
public delegate ValueTask<HttpResponseData> Oid4VciJsonPostDelegate(
    Uri endpoint,
    string jsonBody,
    OutgoingHeaders headers,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Decrypts a §10 JWE-wrapped (Deferred) Credential Response into its plaintext
/// JSON. Wired only when the Wallet asks for an encrypted response by supplying
/// <see cref="CredentialResponseEncryption"/> on the Credential Request;
/// <see langword="null"/> means the Wallet reads a plaintext JSON response. The
/// application owns the ECDH-ES + AES-GCM composition (the crypto-provider
/// delegates live outside the transport-agnostic library).
/// </summary>
/// <param name="compactJwe">The compact JWE from the response body.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The decrypted Credential Response JSON.</returns>
public delegate ValueTask<string> Oid4VciDecryptResponseDelegate(
    string compactJwe,
    CancellationToken cancellationToken);


/// <summary>
/// Encrypts a §8.2 (Deferred) Credential Request body to the Credential Issuer's
/// published <c>credential_request_encryption</c> key, returning the compact JWE
/// the Wallet sends in place of the plaintext JSON. §8.2 / §9.1: "Credential
/// Request encryption MUST be used if the credential_response_encryption
/// parameter is included, to prevent it being substituted by an attacker." Wired
/// whenever the Wallet asks for an encrypted response — the application owns the
/// ECDH-ES (or KEM) + AES-GCM composition behind this delegate.
/// </summary>
/// <param name="requestBody">The plaintext Credential Request JSON to encrypt.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The compact JWE request body.</returns>
public delegate ValueTask<string> Oid4VciEncryptRequestDelegate(
    string requestBody,
    CancellationToken cancellationToken);


/// <summary>
/// Bundles the delegates an <see cref="Oid4VciWalletClient"/> uses to drive
/// OID4VCI 1.0 issuance: the form-POST transport for the §6 Token Request, the
/// JSON-POST transport for the §7 Nonce and §8 Credential Requests, the OPTIONAL
/// §4.1.3 by-reference Credential Offer GET transport, the holder key proof signer
/// plumbing (serializers + encoder), and the OPTIONAL DPoP proof and §10
/// response-decryption drop-outs. Mirrors the shape of
/// <see cref="Oid4Vp.Wallet.Oid4VpWalletConfiguration"/>: one record holds the
/// wallet plumbing, transport-agnostic, with the application owning crypto and
/// transport behind delegates.
/// </summary>
public sealed record Oid4VciWalletConfiguration
{
    /// <summary>Form-POST transport for the §6 Pre-Authorized Code Token Request.</summary>
    public required Oid4VciFormPostDelegate SendFormPost { get; init; }

    /// <summary>
    /// JSON-POST transport for the §7 Nonce Request, the §8 Credential Request, the §9 Deferred
    /// Credential Request, and the §11 Notification Request.
    /// </summary>
    public required Oid4VciJsonPostDelegate SendJsonPost { get; init; }

    /// <summary>
    /// Optional §4.1.3 by-reference Credential Offer GET single-hop transport, driven through the
    /// library's guarded <see cref="Verifiable.Core.OutboundFetch.OutboundFetch"/> chokepoint —
    /// the same seam <see cref="Client.AuthorizationServerMetadataDocuments.ResolveAsync"/> drives —
    /// so the fetch gets that seam's redirect re-validation and per-hop policy evaluation for free.
    /// Required when the Wallet accepts a <c>credential_offer_uri</c> deep link via
    /// <see cref="Oid4VciWalletClient.AcceptCredentialOfferAsync"/>; <see langword="null"/> means the
    /// Wallet only ever consumes a by-value <c>credential_offer</c> it can parse inline.
    /// </summary>
    /// <remarks>
    /// The <c>credential_offer_uri</c> is carried by a §4.1 Credential Offer deep link (a scanned QR
    /// code) — not chosen by this library — and may share an origin with the application's own
    /// backend. A browser host therefore sends every request this transport builds with credentials
    /// omitted, because the Fetch Standard's default credentials mode is <c>same-origin</c>. The
    /// library places no origin restriction on the URI; it evaluates the resolved
    /// <see cref="OutboundFetchPolicy"/> at every hop.
    /// </remarks>
    public OutboundTransportDelegate? FetchCredentialOffer { get; init; }

    /// <summary>
    /// The upper bound, in bytes, the §4.1.3 Credential Offer GET accepts — threaded onto
    /// <see cref="Verifiable.Core.OutboundFetch.OutboundRequest.MaxResponseBytes"/> as the transport
    /// hint and re-checked authoritatively after the read, the same two-layer shape
    /// <see cref="Client.AuthorizationServerMetadataDocuments.ResolveAsync"/> applies to its own
    /// document fetch. A Credential Offer object is a handful of parameters, so the default is
    /// generous relative to any conforming offer while still bounding a hostile or misbehaving
    /// Issuer's response.
    /// </summary>
    public long MaximumCredentialOfferBytes { get; init; } = 65536;

    /// <summary>Serializes the holder proof's JOSE header to UTF-8 JSON bytes.</summary>
    public required JwtHeaderSerializer JwtHeaderSerializer { get; init; }

    /// <summary>Serializes the holder proof's payload to UTF-8 JSON bytes.</summary>
    public required JwtPayloadSerializer JwtPayloadSerializer { get; init; }

    /// <summary>Base64url-without-padding encoder for the holder proof's JWS segments and JWK coordinates.</summary>
    public required EncodeDelegate Base64UrlEncoder { get; init; }

    /// <summary>Time source for the holder proof's <c>iat</c> claim.</summary>
    public required TimeProvider TimeProvider { get; init; }

    /// <summary>Memory pool for transient signing buffers, supplied by the wallet deployment.</summary>
    public required BaseMemoryPool MemoryPool { get; init; }

    /// <summary>
    /// The outbound-fetch policy every dial this Wallet makes is evaluated against when the call's
    /// <see cref="ExchangeContext"/> carries none (see
    /// <see cref="OutboundFetchPolicyExchangeContextExtensions.ResolveOutboundFetchPolicy"/>).
    /// Defaults to <see cref="OutboundFetchPolicy.SecureDefault"/>. The §4.1.3 Credential Offer URI,
    /// and the §6/§7/§8/§9/§11 endpoints read out of a Credential Offer or §12.2 Credential Issuer
    /// Metadata, are named by the Issuer rather than chosen by this library, so a deployment that
    /// talks to a loopback or private-network Issuer names a policy here that allows it.
    /// </summary>
    public OutboundFetchPolicy OutboundFetchPolicy { get; init; } = OutboundFetchPolicy.SecureDefault;

    /// <summary>
    /// Optional RFC 9449 DPoP proof constructor — the same
    /// <see cref="Verifiable.OAuth.Dpop.ConstructDpopProofDelegate"/> seam
    /// <see cref="Verifiable.OAuth.Client.OAuthClientInfrastructure.ConstructDpopProofAsync"/> uses,
    /// so an application wires the library default
    /// (<see cref="Verifiable.OAuth.Dpop.DpopProofConstruction.BuildAsync"/>) or a custom
    /// implementation once for both the AuthCode client and the OID4VCI Wallet. Wired together with
    /// <see cref="DpopKey"/> and <see cref="GenerateIdentifierAsync"/> — all three null or all three
    /// non-null (<see cref="Oid4VciWalletClient(Oid4VciWalletConfiguration)"/> refuses a partial
    /// set); <see langword="null"/> means the Wallet authorizes with a plain <c>Bearer</c> token.
    /// When wired, the §6 Pre-Authorized Code Token Request carries a proof (RFC 9449 §5) and, once
    /// the Token Response returns <c>token_type=DPoP</c>, every §7/§8/§9/§11 resource request does too.
    /// </summary>
    public ConstructDpopProofDelegate? ConstructDpopProofAsync { get; init; }

    /// <summary>
    /// The DPoP signing key. Required, together with <see cref="GenerateIdentifierAsync"/>, when
    /// <see cref="ConstructDpopProofAsync"/> is set; ignored (and must be unset) otherwise.
    /// </summary>
    public DpopKey? DpopKey { get; init; }

    /// <summary>
    /// Mints the DPoP proof's <c>jti</c> claim (RFC 9449 §4.2) for
    /// <see cref="Verifiable.OAuth.Server.WellKnownIdentifierPurposes.OAuthJti"/> — the same
    /// <see cref="Verifiable.OAuth.Client.OAuthClientInfrastructure.GenerateIdentifierAsync"/> seam
    /// the AuthCode client's own DPoP proof minting uses, so a deployment's audit, replay, and
    /// identifier-format choices reach the Wallet's proofs too. Required, together with
    /// <see cref="ConstructDpopProofAsync"/> and <see cref="DpopKey"/>, whenever either of those is
    /// set; ignored (and must be unset) otherwise.
    /// </summary>
    public GenerateIdentifierDelegate? GenerateIdentifierAsync { get; init; }

    /// <summary>
    /// Looks up the latest server-issued DPoP nonce for a given authority (scheme+host+port),
    /// shared by the §6 Token Request and every §7/§8/§9/§11 resource request this Wallet sends.
    /// <see langword="null"/> skips reading a cached nonce — the first attempt against a given
    /// authority then always carries none, exactly as if no nonce had been cached yet.
    /// </summary>
    public DpopNonceLookupDelegate? LookupDpopNonce { get; init; }

    /// <summary>
    /// Stores a server-issued DPoP nonce extracted from a <c>DPoP-Nonce</c> response header.
    /// <see langword="null"/> skips caching — the one allowed retry (RFC 9449 §8/§9) still happens
    /// with the nonce the challenge just supplied; only persistence across calls is skipped.
    /// </summary>
    public DpopNonceStoreDelegate? StoreDpopNonce { get; init; }

    /// <summary>
    /// Optional §10 response-decryption drop-out. Required when the Wallet asks
    /// for an encrypted response via <see cref="CredentialResponseEncryption"/>;
    /// <see langword="null"/> means the Wallet reads a plaintext JSON response.
    /// </summary>
    public Oid4VciDecryptResponseDelegate? DecryptResponse { get; init; }

    /// <summary>
    /// Optional §8.2 request-encryption drop-out. Required when the Wallet asks
    /// for an encrypted response via <see cref="CredentialResponseEncryption"/>:
    /// §8.2 / §9.1 make request encryption a MUST whenever
    /// <c>credential_response_encryption</c> is present, to prevent the response
    /// key being substituted by an attacker. <see langword="null"/> means the
    /// Wallet sends a plaintext request — valid only when it asks for no response
    /// encryption.
    /// </summary>
    public Oid4VciEncryptRequestDelegate? EncryptRequest { get; init; }
}
