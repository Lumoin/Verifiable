using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vci.Wallet;

/// <summary>
/// POSTs an <c>application/x-www-form-urlencoded</c> body to
/// <paramref name="endpoint"/> and returns the HTTP status code and response
/// body. Used by <see cref="Oid4VciWalletClient"/> for the §6 Pre-Authorized
/// Code Token Request. Transport-agnostic: the application supplies an
/// implementation (HttpClient-backed in deployments, Kestrel-loopback in
/// tests); the library composes no <c>System.Net</c> types.
/// </summary>
/// <param name="endpoint">The token endpoint URL.</param>
/// <param name="formFields">The form fields to URL-encode into the request body.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The HTTP status code and response body.</returns>
public delegate ValueTask<(int StatusCode, string Body)> Oid4VciFormPostDelegate(
    Uri endpoint,
    IReadOnlyDictionary<string, string> formFields,
    CancellationToken cancellationToken);


/// <summary>
/// POSTs a JSON body to <paramref name="endpoint"/> with the supplied request
/// headers and returns the HTTP status code, response body, and response
/// <c>Content-Type</c>. Used by <see cref="Oid4VciWalletClient"/> for the §7
/// Nonce Request and the §8 Credential Request — the headers carry the
/// <c>Authorization</c> (and, when DPoP-bound, <c>DPoP</c>) values the client
/// composes. Transport-agnostic: no <c>System.Net</c> in the library.
/// </summary>
/// <param name="endpoint">The endpoint URL.</param>
/// <param name="jsonBody">The JSON request body. Empty for the §7 Nonce Request, which carries no body.</param>
/// <param name="headers">The request header name-to-value pairs the client composed.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The HTTP status code, response body, and response <c>Content-Type</c>.</returns>
public delegate ValueTask<(int StatusCode, string Body, string? ContentType)> Oid4VciJsonPostDelegate(
    Uri endpoint,
    string jsonBody,
    IReadOnlyDictionary<string, string> headers,
    CancellationToken cancellationToken);


/// <summary>
/// Produces an RFC 9449 DPoP proof JWT for the HTTP <paramref name="method"/>
/// against <paramref name="endpoint"/>, optionally bound to the
/// <paramref name="accessToken"/> via the <c>ath</c> claim. Wired only when the
/// Pre-Authorized Code grant returns a DPoP-bound (<c>token_type=DPoP</c>)
/// access token; <see langword="null"/> means the Wallet authorizes with a
/// plain <c>Bearer</c> token.
/// </summary>
/// <param name="method">The HTTP method the proof is bound to (e.g. <c>POST</c>).</param>
/// <param name="endpoint">The endpoint URL the proof's <c>htu</c> claim is bound to.</param>
/// <param name="accessToken">The access token the proof's <c>ath</c> claim binds to, or <see langword="null"/> for an unbound proof.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The compact DPoP proof JWT to place in the <c>DPoP</c> request header.</returns>
public delegate ValueTask<string> Oid4VciDpopProofDelegate(
    string method,
    Uri endpoint,
    string? accessToken,
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
/// GETs the §4.1.3 Credential Offer resource at <paramref name="credentialOfferUri"/> and
/// returns the HTTP status code and response body. Used by
/// <see cref="Oid4VciWalletClient"/> to retrieve a Credential Offer carried by reference:
/// §4.1.3 — "Upon receipt of the credential_offer_uri, the Wallet MUST send an HTTP GET
/// request to the URI to retrieve the referenced Credential Offer Object ... and parse it to
/// recreate the Credential Offer parameters." The response media type is
/// <c>application/json</c>. Transport-agnostic: the application supplies the implementation
/// (HttpClient-backed in deployments, Kestrel-loopback in tests); the library composes no
/// <c>System.Net</c> types.
/// </summary>
/// <param name="credentialOfferUri">The <c>credential_offer_uri</c> the Wallet GETs.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The HTTP status code and response body (the §4.1.1 offer JSON on success).</returns>
public delegate ValueTask<(int StatusCode, string Body)> Oid4VciFetchCredentialOfferDelegate(
    Uri credentialOfferUri,
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
[DebuggerDisplay("Oid4VciWalletConfiguration")]
public sealed record Oid4VciWalletConfiguration
{
    /// <summary>Form-POST transport for the §6 Pre-Authorized Code Token Request.</summary>
    public required Oid4VciFormPostDelegate SendFormPost { get; init; }

    /// <summary>JSON-POST transport for the §7 Nonce Request and §8 Credential Request.</summary>
    public required Oid4VciJsonPostDelegate SendJsonPost { get; init; }

    /// <summary>
    /// Optional §4.1.3 by-reference Credential Offer GET transport. Required when the Wallet
    /// accepts a <c>credential_offer_uri</c> deep link via
    /// <see cref="Oid4VciWalletClient.AcceptCredentialOfferAsync"/>;
    /// <see langword="null"/> means the Wallet only ever consumes a by-value
    /// <c>credential_offer</c> it can parse inline.
    /// </summary>
    public Oid4VciFetchCredentialOfferDelegate? FetchCredentialOffer { get; init; }

    /// <summary>Serializes the holder proof's JOSE header to UTF-8 JSON bytes.</summary>
    public required JwtHeaderSerializer JwtHeaderSerializer { get; init; }

    /// <summary>Serializes the holder proof's payload to UTF-8 JSON bytes.</summary>
    public required JwtPayloadSerializer JwtPayloadSerializer { get; init; }

    /// <summary>Base64url-without-padding encoder for the holder proof's JWS segments and JWK coordinates.</summary>
    public required EncodeDelegate Base64UrlEncoder { get; init; }

    /// <summary>Time source for the holder proof's <c>iat</c> claim. Defaults to <see cref="TimeProvider.System"/>.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>Memory pool for transient signing buffers. Defaults to <see cref="SensitiveMemoryPool{T}.Shared"/>.</summary>
    public MemoryPool<byte> MemoryPool { get; init; } = SensitiveMemoryPool<byte>.Shared;

    /// <summary>
    /// Optional RFC 9449 DPoP proof producer. Required when the §6 Token Response
    /// returns a DPoP-bound access token (<c>token_type=DPoP</c>);
    /// <see langword="null"/> means the Wallet authorizes with a plain
    /// <c>Bearer</c> token.
    /// </summary>
    public Oid4VciDpopProofDelegate? ProduceDpopProof { get; init; }

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
