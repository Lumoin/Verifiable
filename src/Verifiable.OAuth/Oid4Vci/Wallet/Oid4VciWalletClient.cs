using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vci.Wallet;

/// <summary>
/// The OID4VCI 1.0 Wallet-side issuance client. Drives one credential from a
/// §4 Credential Offer's Pre-Authorized Code grant through to the issued
/// Credential string: §6 Pre-Authorized Code Token Request → §7 Nonce Request
/// → §8 Credential Request carrying a §7.2.1 holder key proof, optionally with
/// §10 response encryption. Mirrors the structure of
/// <see cref="Oid4Vp.Wallet.Oid4VpWalletClient"/> — the constructor takes the
/// configuration, and each method drives the flow through the configuration's
/// transport delegates.
/// </summary>
/// <remarks>
/// <para>
/// The client is transport-agnostic: every HTTP exchange goes through a
/// configuration delegate the application supplies, so the library carries no
/// <c>System.Net</c> dependency. The application owns the holder key material
/// and the crypto-provider delegates (signing via the configured serializers,
/// §10 decryption via <see cref="Oid4VciWalletConfiguration.DecryptResponse"/>).
/// </para>
/// <para>
/// This replaces the hand-rolled raw-<c>HttpClient</c> issuance flow with a
/// single call: <see cref="IssuePreAuthorizedAsync"/> takes the offer's
/// pre-authorized grant plus the holder key material and returns the issued
/// Credential.
/// </para>
/// </remarks>
[DebuggerDisplay("Oid4VciWalletClient")]
public sealed class Oid4VciWalletClient
{
    private readonly Oid4VciWalletConfiguration configuration;


    /// <summary>The wallet configuration carrying the transport, signer, and optional DPoP/decrypt delegates.</summary>
    public Oid4VciWalletConfiguration Configuration => configuration;


    /// <summary>
    /// Creates a new OID4VCI Wallet client.
    /// </summary>
    /// <param name="configuration">The wallet delegate bundle.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configuration"/> is <see langword="null"/>.</exception>
    public Oid4VciWalletClient(Oid4VciWalletConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        this.configuration = configuration;
    }


    /// <summary>
    /// Resolves a §4.1 Credential Offer link — carrying the offer either by value
    /// (§4.1.2 <c>credential_offer</c>) or by reference (§4.1.3
    /// <c>credential_offer_uri</c>) — to the <see cref="CredentialOffer"/> model the
    /// issuance path consumes. A by-value link is URL-decoded and parsed inline; a
    /// by-reference link is GET-ed through the configured transport and the returned
    /// <c>application/json</c> offer is parsed.
    /// </summary>
    /// <remarks>
    /// §4.1.3: "Upon receipt of the credential_offer_uri, the Wallet MUST send an HTTP
    /// GET request to the URI to retrieve the referenced Credential Offer Object ... and
    /// parse it to recreate the Credential Offer parameters." §4.1: the link carries a
    /// single query parameter — <c>credential_offer</c> or <c>credential_offer_uri</c>,
    /// never both — and <see cref="CredentialOfferSerializer"/> rejects a link carrying
    /// both. The parsed offer feeds the same downstream issuance as a directly-composed
    /// offer (e.g. <see cref="IssuePreAuthorizedAsync(CredentialOffer, string, PrivateKeyMemory, PublicKeyMemory, Oid4VciIssuanceEndpoints, string?, CredentialResponseEncryption?, CancellationToken)"/>).
    /// </remarks>
    /// <param name="deepLink">The §4.1 Credential Offer deep link the Wallet "scanned".</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The recreated Credential Offer.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the link is by reference but the configuration has no
    /// <see cref="Oid4VciWalletConfiguration.FetchCredentialOffer"/> transport, or the GET
    /// returns a non-success status code.
    /// </exception>
    public async ValueTask<CredentialOffer> AcceptCredentialOfferAsync(
        string deepLink,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(deepLink);

        //§4.1: a link carries either credential_offer_uri (by reference) or credential_offer (by
        //value), never both — TryGetCredentialOfferUri rejects the mutual-exclusion violation.
        if(CredentialOfferSerializer.TryGetCredentialOfferUri(deepLink, out Uri? credentialOfferUri))
        {
            return await FetchCredentialOfferAsync(credentialOfferUri!, cancellationToken).ConfigureAwait(false);
        }

        //§4.1.2: the by-value link (or raw credential_offer value) carries the offer JSON inline.
        return CredentialOfferSerializer.ExtractFromDeepLink(deepLink);
    }


    /// <summary>
    /// GETs the §4.1.3 by-reference Credential Offer at <paramref name="credentialOfferUri"/>
    /// through the configured transport and parses the returned offer JSON.
    /// </summary>
    /// <param name="credentialOfferUri">The <c>credential_offer_uri</c> to retrieve.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The recreated Credential Offer.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no <see cref="Oid4VciWalletConfiguration.FetchCredentialOffer"/> transport is
    /// configured, or the GET returns a non-success status code.
    /// </exception>
    public async ValueTask<CredentialOffer> FetchCredentialOfferAsync(
        Uri credentialOfferUri,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credentialOfferUri);

        if(configuration.FetchCredentialOffer is null)
        {
            throw new InvalidOperationException(
                "§4.1.3 the Wallet MUST send an HTTP GET to the credential_offer_uri to retrieve the "
                + "offer, but the wallet configuration has no FetchCredentialOffer transport. Wire "
                + "Oid4VciWalletConfiguration.FetchCredentialOffer to fetch a by-reference offer.");
        }

        (int statusCode, string body) = await configuration.FetchCredentialOffer(
            credentialOfferUri, cancellationToken).ConfigureAwait(false);

        if(statusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"§4.1.3 Credential Offer GET to {credentialOfferUri} returned HTTP {statusCode}: {body}");
        }

        return CredentialOfferSerializer.FromJson(body);
    }


    /// <summary>
    /// Drives the Pre-Authorized Code issuance flow end-to-end from a §4
    /// <see cref="CredentialOffer"/> and returns the issued Credential string.
    /// The offer MUST carry a <see cref="CredentialOffer.PreAuthorizedCodeGrant"/>.
    /// </summary>
    /// <param name="offer">The Credential Offer the Wallet "scanned".</param>
    /// <param name="credentialConfigurationId">The Credential Configuration to request (one of the offer's ids).</param>
    /// <param name="holderPrivate">The holder's signing private key for the §7.2.1 proof.</param>
    /// <param name="holderPublic">The holder's public key projected into the proof header.</param>
    /// <param name="endpoints">The resolved Token / Nonce / Credential endpoint URLs (§12.2 metadata in deployments).</param>
    /// <param name="transactionCode">The §6.1 <c>tx_code</c>, or <see langword="null"/> when none is required.</param>
    /// <param name="responseEncryption">The §8.2 <c>credential_response_encryption</c> ask, or <see langword="null"/> for a plaintext response.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issued Credential string (the §8.3 <c>credentials[0].credential</c>).</returns>
    public async ValueTask<string> IssuePreAuthorizedAsync(
        CredentialOffer offer,
        string credentialConfigurationId,
        PrivateKeyMemory holderPrivate,
        PublicKeyMemory holderPublic,
        Oid4VciIssuanceEndpoints endpoints,
        string? transactionCode,
        CredentialResponseEncryption? responseEncryption,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(offer);

        if(offer.PreAuthorizedCodeGrant is not PreAuthorizedCodeOfferGrant grant)
        {
            throw new InvalidOperationException(
                "The Credential Offer carries no urn:ietf:params:oauth:grant-type:pre-authorized_code "
                + "grant; IssuePreAuthorizedAsync requires the Pre-Authorized Code Flow.");
        }

        return await IssuePreAuthorizedAsync(
            grant,
            offer.CredentialIssuer,
            credentialConfigurationId,
            holderPrivate,
            holderPublic,
            endpoints,
            transactionCode,
            responseEncryption,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives the Pre-Authorized Code issuance flow from an already-parsed grant
    /// and the Credential Issuer identifier (the proof <c>aud</c>), returning the
    /// issued Credential string.
    /// </summary>
    /// <param name="grant">The offer's Pre-Authorized Code grant carrying the <c>pre-authorized_code</c>.</param>
    /// <param name="credentialIssuer">The Credential Issuer identifier — the holder proof's <c>aud</c>.</param>
    /// <param name="credentialConfigurationId">The Credential Configuration to request.</param>
    /// <param name="holderPrivate">The holder's signing private key for the §7.2.1 proof.</param>
    /// <param name="holderPublic">The holder's public key projected into the proof header.</param>
    /// <param name="endpoints">The resolved Token / Nonce / Credential endpoint URLs.</param>
    /// <param name="transactionCode">The §6.1 <c>tx_code</c>, or <see langword="null"/>.</param>
    /// <param name="responseEncryption">The §8.2 response-encryption ask, or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issued Credential string.</returns>
    public async ValueTask<string> IssuePreAuthorizedAsync(
        PreAuthorizedCodeOfferGrant grant,
        Uri credentialIssuer,
        string credentialConfigurationId,
        PrivateKeyMemory holderPrivate,
        PublicKeyMemory holderPublic,
        Oid4VciIssuanceEndpoints endpoints,
        string? transactionCode,
        CredentialResponseEncryption? responseEncryption,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(credentialIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialConfigurationId);
        ArgumentNullException.ThrowIfNull(holderPrivate);
        ArgumentNullException.ThrowIfNull(holderPublic);
        ArgumentNullException.ThrowIfNull(endpoints);

        //§6: the Pre-Authorized Code grant mints the access token over an HTTP
        //form POST. tx_code rides alongside when the offer required one.
        (string accessToken, string tokenType) = await RequestAccessTokenAsync(
            grant.PreAuthorizedCode, transactionCode, endpoints.TokenEndpoint, cancellationToken)
            .ConfigureAwait(false);

        //§7: the Nonce Endpoint issues the c_nonce the proof must carry.
        string credentialNonce = await RequestNonceAsync(
            accessToken, tokenType, endpoints.NonceEndpoint, cancellationToken).ConfigureAwait(false);

        //§7.2.1: mint the holder key proof bound to the c_nonce and the Issuer.
        string proofJwt = await Oid4VciProofIssuance.BuildJwtProofAsync(
            holderPrivate,
            holderPublic,
            credentialIssuer.OriginalString,
            credentialNonce,
            configuration.TimeProvider.GetUtcNow(),
            configuration.JwtHeaderSerializer,
            configuration.JwtPayloadSerializer,
            configuration.Base64UrlEncoder,
            configuration.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        //§8: the Credential Request — JSON body with the proof, optional §10
        //response encryption, authorized with Bearer or DPoP.
        return await RequestCredentialAsync(
            accessToken,
            tokenType,
            credentialConfigurationId,
            proofJwt,
            responseEncryption,
            endpoints.CredentialEndpoint,
            cancellationToken).ConfigureAwait(false);
    }


    //§6.1.1 Pre-Authorized Code Token Request: grant_type=...pre-authorized_code,
    //the code, and (when required) tx_code, as form fields. Parses access_token
    //and token_type off the JSON Token Response.
    private async ValueTask<(string AccessToken, string TokenType)> RequestAccessTokenAsync(
        string preAuthorizedCode,
        string? transactionCode,
        Uri tokenEndpoint,
        CancellationToken cancellationToken)
    {
        Dictionary<string, string> formFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypePreAuthorizedCode,
            [OAuthRequestParameterNames.PreAuthorizedCode] = preAuthorizedCode
        };

        if(!string.IsNullOrEmpty(transactionCode))
        {
            formFields[OAuthRequestParameterNames.TxCode] = transactionCode;
        }

        (int statusCode, string body) = await configuration.SendFormPost(
            tokenEndpoint, formFields, cancellationToken).ConfigureAwait(false);

        if(statusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"§6 Pre-Authorized Code Token Request to {tokenEndpoint} returned HTTP {statusCode}: {body}");
        }

        ReadOnlySpan<byte> tokenJson = Encoding.UTF8.GetBytes(body);
        string accessToken = JwkJsonReader.ExtractStringValue(tokenJson, WellKnownTokenTypes.AccessTokenUtf8)
            ?? throw new InvalidOperationException(
                $"§6 Token Response from {tokenEndpoint} carried no access_token. Body: {body}");

        //RFC 6749 §5.1 token_type defaults to Bearer when the AS omits it.
        string tokenType = JwkJsonReader.ExtractStringValue(tokenJson, OAuthRequestParameterNames.TokenTypeUtf8)
            ?? WellKnownAuthenticationSchemes.Bearer;

        return (accessToken, tokenType);
    }


    //§7.1 Nonce Request: an authorized POST with no body; reads c_nonce off the
    //JSON Nonce Response.
    private async ValueTask<string> RequestNonceAsync(
        string accessToken,
        string tokenType,
        Uri nonceEndpoint,
        CancellationToken cancellationToken)
    {
        IReadOnlyDictionary<string, string> headers = await ComposeAuthorizationHeadersAsync(
            accessToken, tokenType, nonceEndpoint, cancellationToken).ConfigureAwait(false);

        (int statusCode, string body, _) = await configuration.SendJsonPost(
            nonceEndpoint, string.Empty, headers, cancellationToken).ConfigureAwait(false);

        if(statusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"§7 Nonce Request to {nonceEndpoint} returned HTTP {statusCode}: {body}");
        }

        return JwkJsonReader.ExtractStringValue(Encoding.UTF8.GetBytes(body), CNonceUtf8)
            ?? throw new InvalidOperationException(
                $"§7 Nonce Response from {nonceEndpoint} carried no c_nonce. Body: {body}");
    }


    //§8.2 Credential Request: JSON body { credential_configuration_id,
    //proofs:{jwt:[proof]}, credential_response_encryption? }. Reads
    //credentials[0].credential off the (optionally decrypted) response.
    private async ValueTask<string> RequestCredentialAsync(
        string accessToken,
        string tokenType,
        string credentialConfigurationId,
        string proofJwt,
        CredentialResponseEncryption? responseEncryption,
        Uri credentialEndpoint,
        CancellationToken cancellationToken)
    {
        string requestBody = BuildCredentialRequestBody(
            credentialConfigurationId, proofJwt, responseEncryption);

        //§8.2: "Credential Request encryption MUST be used if the
        //credential_response_encryption parameter is included, to prevent it being
        //substituted by an attacker." So when the Wallet asks for an encrypted
        //response it MUST send the request itself encrypted — the EncryptRequest
        //seam wraps the body as a JWE to the Issuer's request-encryption key.
        if(responseEncryption is not null)
        {
            if(configuration.EncryptRequest is null)
            {
                throw new InvalidOperationException(
                    "The Credential Request asks for §10 response encryption, so §8.2 requires the "
                    + "request itself to be encrypted, but the wallet configuration has no "
                    + "EncryptRequest delegate. Wire Oid4VciWalletConfiguration.EncryptRequest to "
                    + "encrypt the request to the Issuer's credential_request_encryption key.");
            }

            requestBody = await configuration.EncryptRequest(requestBody, cancellationToken).ConfigureAwait(false);
        }

        IReadOnlyDictionary<string, string> headers = await ComposeAuthorizationHeadersAsync(
            accessToken, tokenType, credentialEndpoint, cancellationToken).ConfigureAwait(false);

        (int statusCode, string body, string? contentType) = await configuration.SendJsonPost(
            credentialEndpoint, requestBody, headers, cancellationToken).ConfigureAwait(false);

        if(statusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"§8 Credential Request to {credentialEndpoint} returned HTTP {statusCode}: {body}");
        }

        //§10: when the Wallet asked for encryption the response is a JWE with
        //media type application/jwt — decrypt it to the plaintext JSON before
        //reading the credential. The application owns the decryption composition.
        string responseJson = body;
        if(responseEncryption is not null)
        {
            if(configuration.DecryptResponse is null)
            {
                throw new InvalidOperationException(
                    "The Credential Request asked for §10 response encryption but the wallet "
                    + "configuration has no DecryptResponse delegate. Wire "
                    + "Oid4VciWalletConfiguration.DecryptResponse to read an encrypted response.");
            }

            //§8.3 / §9.2: an encrypted response is application/jwt regardless of
            //content; refuse a clear answer to an encryption ask rather than
            //misreading it.
            if(contentType is not null
                && !contentType.Contains(WellKnownMediaTypes.Application.Jwt, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"§10 encryption was requested but the response Content-Type was '{contentType}', "
                    + $"not '{WellKnownMediaTypes.Application.Jwt}'. The Issuer did not encrypt the response.");
            }

            responseJson = await configuration.DecryptResponse(body, cancellationToken).ConfigureAwait(false);
        }

        //§8.3 credentials is an array of objects, each carrying a credential
        //member; read the first object's credential string. JwkJsonReader's
        //array-of-objects scanner matches the {"credentials":[{"credential":...}]}
        //shape exactly, keeping the wallet free of System.Text.Json.
        return JwkJsonReader.ExtractNestedStringValueFromArray(
            Encoding.UTF8.GetBytes(responseJson),
            Oid4VciCredentialParameterNames.CredentialsUtf8,
            Oid4VciCredentialParameterNames.CredentialUtf8)
            ?? throw new InvalidOperationException(
                $"§8 Credential Response from {credentialEndpoint} carried no credentials[0].credential. "
                + $"Body: {responseJson}");
    }


    //Composes the request headers carrying the access-token authorization.
    //RFC 6750: a Bearer token rides Authorization: Bearer <token>. RFC 9449
    //§7.1: a DPoP-bound token rides Authorization: DPoP <token> alongside a
    //fresh DPoP proof in the DPoP header — wired only when the token is
    //DPoP-bound and a proof producer is configured.
    private async ValueTask<IReadOnlyDictionary<string, string>> ComposeAuthorizationHeadersAsync(
        string accessToken,
        string tokenType,
        Uri endpoint,
        CancellationToken cancellationToken)
    {
        Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);

        if(WellKnownAuthenticationSchemes.IsDPoP(tokenType) && configuration.ProduceDpopProof is not null)
        {
            string dpopProof = await configuration.ProduceDpopProof(
                HttpPostMethod, endpoint, accessToken, cancellationToken).ConfigureAwait(false);

            headers[WellKnownHttpHeaderNames.Authorization] =
                $"{WellKnownAuthenticationSchemes.DPoP} {accessToken}";
            headers[WellKnownHttpHeaderNames.DPoP] = dpopProof;

            return headers;
        }

        headers[WellKnownHttpHeaderNames.Authorization] =
            $"{WellKnownAuthenticationSchemes.Bearer} {accessToken}";

        return headers;
    }


    //Builds the §8.2 Credential Request JSON body without System.Text.Json — the
    //Verifiable.OAuth serialization firewall. The proof and config id are
    //JSON-safe wire values (a compact JWS and a metadata key); the optional
    //credential_response_encryption object is appended verbatim from its members.
    private static string BuildCredentialRequestBody(
        string credentialConfigurationId,
        string proofJwt,
        CredentialResponseEncryption? responseEncryption)
    {
        StringBuilder builder = new();
        builder.Append('{');
        builder.Append('"').Append(Oid4VciCredentialParameterNames.CredentialConfigurationId).Append("\":\"");
        builder.Append(credentialConfigurationId).Append("\",");
        builder.Append('"').Append(Oid4VciCredentialParameterNames.Proofs).Append("\":{\"");
        builder.Append(Oid4VciCredentialParameterNames.JwtProofType).Append("\":[\"");
        builder.Append(proofJwt).Append("\"]}");

        if(responseEncryption is { Jwk: { } jwk, Enc: { } enc })
        {
            builder.Append(",\"").Append(Oid4VciCredentialParameterNames.CredentialResponseEncryption);
            builder.Append("\":{\"").Append(Oid4VciCredentialParameterNames.Jwk).Append("\":{");
            bool first = true;
            foreach(KeyValuePair<string, object> member in jwk)
            {
                if(!first)
                {
                    builder.Append(',');
                }

                builder.Append('"').Append(member.Key).Append("\":\"").Append(member.Value).Append('"');
                first = false;
            }

            builder.Append("},\"").Append(Oid4VciCredentialParameterNames.Enc).Append("\":\"");
            builder.Append(enc).Append("\"}");
        }

        builder.Append('}');

        return builder.ToString();
    }


    //The HTTP method the DPoP proof binds to for the authorized POST endpoints.
    private const string HttpPostMethod = "POST";


    //c_nonce is the §7 Nonce Response member carrying the proof challenge. The
    //Nonce Endpoint emits it as a bare literal; no shared constant exists to
    //reuse, so the Wallet names the same wire key here.
    private static ReadOnlySpan<byte> CNonceUtf8 => "c_nonce"u8;
}


/// <summary>
/// The resolved OID4VCI endpoint URLs an <see cref="Oid4VciWalletClient"/> drives
/// against. In deployments the Wallet resolves these from §12.2 Credential Issuer
/// Metadata; the client takes them pre-resolved so it stays transport-agnostic.
/// </summary>
[DebuggerDisplay("Oid4VciIssuanceEndpoints")]
public sealed record Oid4VciIssuanceEndpoints
{
    /// <summary>The §6 Token Endpoint URL for the Pre-Authorized Code grant.</summary>
    public required Uri TokenEndpoint { get; init; }

    /// <summary>The §7 Nonce Endpoint URL.</summary>
    public required Uri NonceEndpoint { get; init; }

    /// <summary>The §8 Credential Endpoint URL.</summary>
    public required Uri CredentialEndpoint { get; init; }
}
