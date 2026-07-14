using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Server;

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


    /// <summary>The wallet configuration carrying the transport, signer, and optional DPoP/decrypt delegates.</summary>
    public Oid4VciWalletConfiguration Configuration { get; }


    /// <summary>
    /// Creates a new OID4VCI Wallet client.
    /// </summary>
    /// <param name="configuration">The wallet delegate bundle.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configuration"/> is <see langword="null"/>.</exception>
    public Oid4VciWalletClient(Oid4VciWalletConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        this.Configuration = configuration;
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

        if(Configuration.FetchCredentialOffer is null)
        {
            throw new InvalidOperationException(
                "§4.1.3 the Wallet MUST send an HTTP GET to the credential_offer_uri to retrieve the "
                + "offer, but the wallet configuration has no FetchCredentialOffer transport. Wire "
                + "Oid4VciWalletConfiguration.FetchCredentialOffer to fetch a by-reference offer.");
        }

        (int statusCode, string body) = await Configuration.FetchCredentialOffer(
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
    /// Drives the Pre-Authorized Code issuance flow from a §4 <see cref="CredentialOffer"/> and returns
    /// the full §8.3 outcome (every batch Credential, the §11 <c>notification_id</c>, or a §9 deferral).
    /// The offer MUST carry a <see cref="CredentialOffer.PreAuthorizedCodeGrant"/>.
    /// </summary>
    /// <param name="offer">The Credential Offer the Wallet "scanned".</param>
    /// <param name="credentialConfigurationId">The Credential Configuration to request (one of the offer's ids).</param>
    /// <param name="holderPrivate">The holder's signing private key for the §7.2.1 proof.</param>
    /// <param name="holderPublic">The holder's public key projected into the proof header.</param>
    /// <param name="endpoints">The resolved Token / Nonce / Credential endpoint URLs.</param>
    /// <param name="transactionCode">The §6.1 <c>tx_code</c>, or <see langword="null"/> when none is required.</param>
    /// <param name="responseEncryption">The §8.2 <c>credential_response_encryption</c> ask, or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The full Credential Response outcome.</returns>
    public async ValueTask<CredentialIssuanceResult> IssuePreAuthorizedDetailedAsync(
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
                + "grant; IssuePreAuthorizedDetailedAsync requires the Pre-Authorized Code Flow.");
        }

        return await IssuePreAuthorizedDetailedAsync(
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
    /// <returns>The issued Credential string (the §8.3 <c>credentials[0].credential</c>).</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the issuance was deferred or produced no Credential — use
    /// <see cref="IssuePreAuthorizedDetailedAsync(PreAuthorizedCodeOfferGrant, Uri, string, PrivateKeyMemory, PublicKeyMemory, Oid4VciIssuanceEndpoints, string?, CredentialResponseEncryption?, CancellationToken)"/>
    /// to handle a §9 deferral, a §8.2 batch, or the §11 <c>notification_id</c>.
    /// </exception>
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
        CredentialIssuanceResult result = await IssuePreAuthorizedDetailedAsync(
            grant,
            credentialIssuer,
            credentialConfigurationId,
            holderPrivate,
            holderPublic,
            endpoints,
            transactionCode,
            responseEncryption,
            cancellationToken).ConfigureAwait(false);

        if(result.IsDeferred)
        {
            throw new InvalidOperationException(
                "§9 the issuance was deferred (transaction_id "
                + $"'{result.TransactionId}'); IssuePreAuthorizedAsync returns a single Credential. "
                + "Use IssuePreAuthorizedDetailedAsync and poll with PollDeferredCredentialAsync.");
        }

        if(!result.IsIssued)
        {
            throw new InvalidOperationException(
                "§8.3 the Credential Response carried no credentials[0].credential.");
        }

        return result.Credentials[0];
    }


    /// <summary>
    /// Drives the Pre-Authorized Code issuance flow from an already-parsed grant and the Credential
    /// Issuer identifier (the proof <c>aud</c>), returning the full §8.3 outcome: every issued
    /// Credential of a §8.2 batch, the §11 <c>notification_id</c>, or a §9 deferral's
    /// <c>transaction_id</c>.
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
    /// <returns>The full Credential Response outcome.</returns>
    public async ValueTask<CredentialIssuanceResult> IssuePreAuthorizedDetailedAsync(
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
            Configuration.TimeProvider.GetUtcNow(),
            Configuration.JwtHeaderSerializer,
            Configuration.JwtPayloadSerializer,
            Configuration.Base64UrlEncoder,
            Configuration.MemoryPool,
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


    /// <summary>
    /// Sends the <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1.1">§6.1.1</see>
    /// Pre-Authorized Code Token Request — <c>grant_type=...pre-authorized_code</c>, the code, and
    /// (when required) <c>tx_code</c> as form fields — and parses <c>access_token</c> and
    /// <c>token_type</c> off the JSON Token Response.
    /// </summary>
    private async ValueTask<(string AccessToken, string TokenType)> RequestAccessTokenAsync(
        string preAuthorizedCode,
        string? transactionCode,
        Uri tokenEndpoint,
        CancellationToken cancellationToken)
    {
        Dictionary<string, string> formFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
            [OAuthRequestParameterNames.PreAuthorizedCode] = preAuthorizedCode
        };

        if(!string.IsNullOrEmpty(transactionCode))
        {
            formFields[OAuthRequestParameterNames.TxCode] = transactionCode;
        }

        (int statusCode, string body) = await Configuration.SendFormPost(
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


    /// <summary>
    /// Sends the <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.1">§7.1</see>
    /// Nonce Request — an authorized POST with no body — and reads <c>c_nonce</c> off the JSON Nonce
    /// Response.
    /// </summary>
    private async ValueTask<string> RequestNonceAsync(
        string accessToken,
        string tokenType,
        Uri nonceEndpoint,
        CancellationToken cancellationToken)
    {
        IReadOnlyDictionary<string, string> headers = await ComposeAuthorizationHeadersAsync(
            accessToken, tokenType, nonceEndpoint, cancellationToken).ConfigureAwait(false);

        (int statusCode, string body, _) = await Configuration.SendJsonPost(
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


    /// <summary>
    /// Sends the <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">§8.2</see>
    /// Credential Request — JSON body <c>{ credential_configuration_id, proofs:{jwt:[proof]},
    /// credential_response_encryption? }</c> — and parses the full
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3">§8.3</see>
    /// response (every batch credential and the <c>notification_id</c>), or the
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9.2">§9.2</see>
    /// HTTP 202 deferral carrying <c>transaction_id</c> + <c>interval</c>.
    /// </summary>
    private async ValueTask<CredentialIssuanceResult> RequestCredentialAsync(
        string accessToken,
        string tokenType,
        string credentialConfigurationId,
        string proofJwt,
        CredentialResponseEncryption? responseEncryption,
        Uri credentialEndpoint,
        CancellationToken cancellationToken)
    {
        string requestBody = await EncryptRequestIfAskedAsync(
            BuildCredentialRequestBody(credentialConfigurationId, proofJwt, responseEncryption),
            responseEncryption,
            cancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<string, string> headers = await ComposeAuthorizationHeadersAsync(
            accessToken, tokenType, credentialEndpoint, cancellationToken).ConfigureAwait(false);

        (int statusCode, string body, string? contentType) = await Configuration.SendJsonPost(
            credentialEndpoint, requestBody, headers, cancellationToken).ConfigureAwait(false);

        //§8.3: a deferral answers HTTP 202 with transaction_id + interval (plaintext metadata, not the
        //encrypted credential payload); the Wallet later polls the Deferred Credential Endpoint.
        if(statusCode == HttpAcceptedStatusCode)
        {
            return ParseDeferredPending(body, accessToken, tokenType, credentialEndpoint);
        }

        if(statusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"§8 Credential Request to {credentialEndpoint} returned HTTP {statusCode}: {body}");
        }

        string responseJson = await DecryptResponseIfAskedAsync(
            body, contentType, responseEncryption, cancellationToken).ConfigureAwait(false);

        return ParseIssuedCredentials(responseJson, accessToken, tokenType, credentialEndpoint);
    }


    /// <summary>
    /// Polls the OID4VCI 1.0 §9 Deferred Credential Endpoint for a previously-deferred issuance,
    /// presenting the <c>transaction_id</c> a prior <see cref="CredentialIssuanceResult"/> carried.
    /// Returns the issued Credentials when ready (§9.2 HTTP 200), or a still-deferred result echoing the
    /// <c>transaction_id</c> and <c>interval</c> when the Issuer answers §9.2 HTTP 202.
    /// </summary>
    /// <param name="transactionId">The §9.1 <c>transaction_id</c> from the deferred issuance.</param>
    /// <param name="accessToken">The issuance access token (from <see cref="CredentialIssuanceResult.AccessToken"/>).</param>
    /// <param name="tokenType">The access token's type (<c>Bearer</c> or <c>DPoP</c>).</param>
    /// <param name="deferredCredentialEndpoint">The §9 Deferred Credential Endpoint URL.</param>
    /// <param name="responseEncryption">The §8.2 response-encryption ask carried over from issuance, or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The issued Credentials, or a still-deferred result to poll again after the interval.</returns>
    public async ValueTask<CredentialIssuanceResult> PollDeferredCredentialAsync(
        string transactionId,
        string accessToken,
        string tokenType,
        Uri deferredCredentialEndpoint,
        CredentialResponseEncryption? responseEncryption,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(transactionId);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenType);
        ArgumentNullException.ThrowIfNull(deferredCredentialEndpoint);

        string requestBody = await EncryptRequestIfAskedAsync(
            BuildDeferredRequestBody(transactionId), responseEncryption, cancellationToken).ConfigureAwait(false);

        IReadOnlyDictionary<string, string> headers = await ComposeAuthorizationHeadersAsync(
            accessToken, tokenType, deferredCredentialEndpoint, cancellationToken).ConfigureAwait(false);

        (int statusCode, string body, string? contentType) = await Configuration.SendJsonPost(
            deferredCredentialEndpoint, requestBody, headers, cancellationToken).ConfigureAwait(false);

        //§9.2: still pending answers HTTP 202 echoing the transaction_id with a fresh interval.
        if(statusCode == HttpAcceptedStatusCode)
        {
            return ParseDeferredPending(body, accessToken, tokenType, deferredCredentialEndpoint);
        }

        if(statusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"§9 Deferred Credential Request to {deferredCredentialEndpoint} returned HTTP {statusCode}: {body}");
        }

        string responseJson = await DecryptResponseIfAskedAsync(
            body, contentType, responseEncryption, cancellationToken).ConfigureAwait(false);

        return ParseIssuedCredentials(responseJson, accessToken, tokenType, deferredCredentialEndpoint);
    }


    /// <summary>
    /// Sends an OID4VCI 1.0 §11 Notification Request reporting what became of the issued Credentials,
    /// identified by the <c>notification_id</c> a <see cref="CredentialIssuanceResult"/> carried.
    /// </summary>
    /// <param name="notificationId">The §8.3 <c>notification_id</c> from the issuance.</param>
    /// <param name="notificationEvent">The §11.1 <c>event</c> — one of <see cref="Oid4VciNotificationEvents"/>.</param>
    /// <param name="accessToken">The issuance access token (from <see cref="CredentialIssuanceResult.AccessToken"/>).</param>
    /// <param name="tokenType">The access token's type (<c>Bearer</c> or <c>DPoP</c>).</param>
    /// <param name="notificationEndpoint">The §11 Notification Endpoint URL.</param>
    /// <param name="eventDescription">The §11.1 <c>event_description</c> (OPTIONAL human-readable text), or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">Thrown when the Notification Endpoint returns a non-success status (§11.3).</exception>
    public async ValueTask SendCredentialNotificationAsync(
        string notificationId,
        string notificationEvent,
        string accessToken,
        string tokenType,
        Uri notificationEndpoint,
        string? eventDescription,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(notificationId);
        ArgumentException.ThrowIfNullOrWhiteSpace(notificationEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenType);
        ArgumentNullException.ThrowIfNull(notificationEndpoint);

        string requestBody = BuildNotificationRequestBody(notificationId, notificationEvent, eventDescription);

        IReadOnlyDictionary<string, string> headers = await ComposeAuthorizationHeadersAsync(
            accessToken, tokenType, notificationEndpoint, cancellationToken).ConfigureAwait(false);

        (int statusCode, string body, _) = await Configuration.SendJsonPost(
            notificationEndpoint, requestBody, headers, cancellationToken).ConfigureAwait(false);

        //§11.2: success is HTTP 204 No Content; §11.3 maps failures to error bodies.
        if(statusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"§11 Notification Request to {notificationEndpoint} returned HTTP {statusCode}: {body}");
        }
    }


    /// <summary>
    /// Encrypts the request body when response encryption was asked for.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">§8.2</see>:
    /// "Credential Request encryption MUST be used if the credential_response_encryption parameter is
    /// included, to prevent it being substituted by an attacker." The <c>EncryptRequest</c> seam wraps
    /// the body as a JWE to the Issuer's request-encryption key.
    /// </summary>
    private async ValueTask<string> EncryptRequestIfAskedAsync(
        string requestBody,
        CredentialResponseEncryption? responseEncryption,
        CancellationToken cancellationToken)
    {
        if(responseEncryption is null)
        {
            return requestBody;
        }

        if(Configuration.EncryptRequest is null)
        {
            throw new InvalidOperationException(
                "The request asks for §10 response encryption, so §8.2 requires the request itself to "
                + "be encrypted, but the wallet configuration has no EncryptRequest delegate. Wire "
                + "Oid4VciWalletConfiguration.EncryptRequest to encrypt the request to the Issuer's "
                + "credential_request_encryption key.");
        }

        return await Configuration.EncryptRequest(requestBody, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Decrypts the response when encryption was asked for. Per
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10">§10</see>
    /// an encrypted response is a JWE with media type <c>application/jwt</c>; this decrypts it to the
    /// plaintext JSON before the credentials are read. The application owns the decryption composition.
    /// </summary>
    private async ValueTask<string> DecryptResponseIfAskedAsync(
        string body,
        string? contentType,
        CredentialResponseEncryption? responseEncryption,
        CancellationToken cancellationToken)
    {
        if(responseEncryption is null)
        {
            return body;
        }

        if(Configuration.DecryptResponse is null)
        {
            throw new InvalidOperationException(
                "The request asked for §10 response encryption but the wallet configuration has no "
                + "DecryptResponse delegate. Wire Oid4VciWalletConfiguration.DecryptResponse to read an "
                + "encrypted response.");
        }

        //§8.3 / §9.2: an encrypted response is application/jwt regardless of content; refuse a clear
        //answer to an encryption ask rather than misreading it.
        if(contentType is not null
            && !contentType.Contains(WellKnownMediaTypes.Application.Jwt, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"§10 encryption was requested but the response Content-Type was '{contentType}', "
                + $"not '{WellKnownMediaTypes.Application.Jwt}'. The Issuer did not encrypt the response.");
        }

        return await Configuration.DecryptResponse(body, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Parses an issued-credentials response.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3">§8.3</see>:
    /// <c>credentials</c> is an array of objects each carrying a <c>credential</c> member; this reads
    /// EVERY object's credential string (a §8.2 batch carries more than one) plus the optional
    /// <c>notification_id</c>. The <see cref="JwkJsonReader"/> array-of-objects scanner keeps the wallet
    /// free of <c>System.Text.Json</c>.
    /// </summary>
    private static CredentialIssuanceResult ParseIssuedCredentials(
        string responseJson,
        string accessToken,
        string tokenType,
        Uri endpoint)
    {
        ReadOnlySpan<byte> json = Encoding.UTF8.GetBytes(responseJson);

        List<string>? credentials = JwkJsonReader.ExtractNestedStringValuesFromArray(
            json,
            Oid4VciCredentialParameterNames.CredentialsUtf8,
            Oid4VciCredentialParameterNames.CredentialUtf8);

        if(credentials is null || credentials.Count == 0)
        {
            throw new InvalidOperationException(
                $"§8 Credential Response from {endpoint} carried no credentials[].credential. "
                + $"Body: {responseJson}");
        }

        string? notificationId = JwkJsonReader.ExtractStringValue(
            json, Oid4VciCredentialParameterNames.NotificationIdUtf8);

        return new CredentialIssuanceResult
        {
            Credentials = credentials,
            NotificationId = notificationId,
            AccessToken = accessToken,
            TokenType = tokenType
        };
    }


    /// <summary>
    /// Parses a deferral response.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3">§8.3</see>
    /// / <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9.2">§9.2</see>:
    /// a deferral carries <c>transaction_id</c> (REQUIRED) and <c>interval</c> (REQUIRED alongside it).
    /// </summary>
    private static CredentialIssuanceResult ParseDeferredPending(
        string body,
        string accessToken,
        string tokenType,
        Uri endpoint)
    {
        ReadOnlySpan<byte> json = Encoding.UTF8.GetBytes(body);

        string transactionId = JwkJsonReader.ExtractStringValue(
            json, Oid4VciCredentialParameterNames.TransactionIdUtf8)
            ?? throw new InvalidOperationException(
                $"§9 deferral from {endpoint} carried no transaction_id. Body: {body}");

        int? interval = JwkJsonReader.TryExtractLongValue(
            json, Oid4VciCredentialParameterNames.IntervalUtf8, out long intervalSeconds)
            ? (int)intervalSeconds
            : null;

        return new CredentialIssuanceResult
        {
            TransactionId = transactionId,
            DeferredIntervalSeconds = interval,
            AccessToken = accessToken,
            TokenType = tokenType
        };
    }


    /// <summary>
    /// Builds the <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9.1">§9.1</see>
    /// Deferred Credential Request body — <c>{ transaction_id }</c>.
    /// </summary>
    private static string BuildDeferredRequestBody(string transactionId)
    {
        StringBuilder builder = new();
        builder.Append('{');
        builder.Append('"').Append(Oid4VciCredentialParameterNames.TransactionId).Append("\":\"");
        builder.Append(transactionId).Append("\"}");

        return builder.ToString();
    }


    /// <summary>
    /// Builds the <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.1">§11.1</see>
    /// Notification Request body — <c>{ notification_id, event, event_description? }</c>. The id and
    /// event are JSON-safe wire values; an <c>event_description</c> is escaped as it may carry arbitrary
    /// ASCII text.
    /// </summary>
    private static string BuildNotificationRequestBody(
        string notificationId,
        string notificationEvent,
        string? eventDescription)
    {
        StringBuilder builder = new();
        builder.Append('{');
        builder.Append('"').Append(Oid4VciCredentialParameterNames.NotificationId).Append("\":\"");
        builder.Append(notificationId).Append("\",\"");
        builder.Append(Oid4VciCredentialParameterNames.Event).Append("\":\"");
        builder.Append(notificationEvent).Append('"');

        if(!string.IsNullOrEmpty(eventDescription))
        {
            builder.Append(",\"").Append(Oid4VciCredentialParameterNames.EventDescription).Append("\":\"");
            JsonAppender.AppendEscapedString(builder, eventDescription);
            builder.Append('"');
        }

        builder.Append('}');

        return builder.ToString();
    }


    /// <summary>
    /// Composes the request headers carrying the access-token authorization.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750">RFC 6750</see>: a Bearer token rides
    /// <c>Authorization: Bearer &lt;token&gt;</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 §7.1</see>: a DPoP-bound
    /// token rides <c>Authorization: DPoP &lt;token&gt;</c> alongside a fresh DPoP proof in the
    /// <c>DPoP</c> header — wired only when the token is DPoP-bound and a proof producer is configured.
    /// </summary>
    private async ValueTask<IReadOnlyDictionary<string, string>> ComposeAuthorizationHeadersAsync(
        string accessToken,
        string tokenType,
        Uri endpoint,
        CancellationToken cancellationToken)
    {
        Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);

        if(WellKnownAuthenticationSchemes.IsDPoP(tokenType) && Configuration.ProduceDpopProof is not null)
        {
            string dpopProof = await Configuration.ProduceDpopProof(
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


    /// <summary>
    /// Builds the <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">§8.2</see>
    /// Credential Request JSON body without <c>System.Text.Json</c> — the <c>Verifiable.OAuth</c>
    /// serialization firewall. The proof and config id are JSON-safe wire values (a compact JWS and a
    /// metadata key); the optional <c>credential_response_encryption</c> object is appended verbatim
    /// from its members.
    /// </summary>
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


    /// <summary>The HTTP method the DPoP proof binds to for the authorized POST endpoints.</summary>
    private const string HttpPostMethod = "POST";

    /// <summary>The HTTP 202 Accepted status code an Issuer answers with to defer issuance (§8.3 / §9.2).</summary>
    private const int HttpAcceptedStatusCode = 202;

    /// <summary>
    /// The <c>c_nonce</c> §7 Nonce Response member carrying the proof challenge. The Nonce Endpoint
    /// emits it as a bare literal; no shared constant exists to reuse, so the Wallet names the same wire
    /// key here.
    /// </summary>
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
