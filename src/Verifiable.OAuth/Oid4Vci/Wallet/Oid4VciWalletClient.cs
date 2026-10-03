using System.Text;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;

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
/// single call:
/// <see cref="IssuePreAuthorizedAsync(CredentialOffer, string, PrivateKeyMemory, PublicKeyMemory, Oid4VciIssuanceEndpoints, string?, CredentialResponseEncryption?, ExchangeContext, CancellationToken)"/>
/// takes the offer's pre-authorized grant plus the holder key material and returns the issued
/// Credential.
/// </para>
/// <para>
/// A Credential Request names what it asks for through one <see cref="CredentialRequestTarget"/>,
/// so it cannot name both <c>credential_configuration_id</c> and <c>credential_identifier</c>, or
/// neither. The Pre-Authorized Code entry points read their Token Response's
/// <c>authorization_details</c> with the span reader and request by the first
/// <c>credential_identifiers</c> value granted for the requested configuration, by the configuration
/// when the response returned no <c>openid_credential</c> object, and send no request when the
/// response granted identifiers for other configurations only.
/// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
/// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
/// Requests."
/// </para>
/// </remarks>
public sealed class Oid4VciWalletClient
{


    /// <summary>The wallet configuration carrying the transport, signer, and optional DPoP/decrypt delegates.</summary>
    public Oid4VciWalletConfiguration Configuration { get; }


    /// <summary>
    /// Creates a new OID4VCI Wallet client.
    /// </summary>
    /// <param name="configuration">The wallet delegate bundle.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configuration"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="configuration"/> wires only some of
    /// <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>,
    /// <see cref="Oid4VciWalletConfiguration.DpopKey"/>, and
    /// <see cref="Oid4VciWalletConfiguration.GenerateIdentifierAsync"/> — the three are wired
    /// together or not at all.
    /// </exception>
    public Oid4VciWalletClient(Oid4VciWalletConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        EnsureDpopWiringIsComplete(configuration);

        this.Configuration = configuration;
    }


    /// <summary>
    /// Refuses a partially-wired DPoP configuration.
    /// <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>,
    /// <see cref="Oid4VciWalletConfiguration.DpopKey"/>, and
    /// <see cref="Oid4VciWalletConfiguration.GenerateIdentifierAsync"/> must be set together or not
    /// at all: a configuration carrying one or two of the three without the rest would otherwise
    /// silently degrade to a plain Bearer request instead of the RFC 9449 §5 sender-constrained one
    /// the deployment asked for.
    /// </summary>
    /// <param name="configuration">The configuration to check.</param>
    /// <exception cref="ArgumentException">Thrown naming the missing member when the three are not all set or all unset.</exception>
    private static void EnsureDpopWiringIsComplete(Oid4VciWalletConfiguration configuration)
    {
        bool hasConstructDpopProofAsync = configuration.ConstructDpopProofAsync is not null;
        bool hasDpopKey = configuration.DpopKey is not null;
        bool hasGenerateIdentifierAsync = configuration.GenerateIdentifierAsync is not null;

        if(hasConstructDpopProofAsync == hasDpopKey && hasDpopKey == hasGenerateIdentifierAsync)
        {
            return;
        }

        string missingMember = (hasConstructDpopProofAsync, hasDpopKey, hasGenerateIdentifierAsync) switch
        {
            (false, _, _) => nameof(Oid4VciWalletConfiguration.ConstructDpopProofAsync),
            (_, false, _) => nameof(Oid4VciWalletConfiguration.DpopKey),
            _ => nameof(Oid4VciWalletConfiguration.GenerateIdentifierAsync)
        };

        throw new ArgumentException(
            "RFC 9449 §5 sender-constraining wires ConstructDpopProofAsync, DpopKey, and "
            + $"GenerateIdentifierAsync together or not at all; {missingMember} is not set while at "
            + "least one of the other two is.",
            nameof(configuration));
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
    /// offer (e.g. <see cref="IssuePreAuthorizedAsync(CredentialOffer, string, PrivateKeyMemory, PublicKeyMemory, Oid4VciIssuanceEndpoints, string?, CredentialResponseEncryption?, ExchangeContext, CancellationToken)"/>).
    /// </remarks>
    /// <param name="deepLink">The §4.1 Credential Offer deep link the Wallet "scanned".</param>
    /// <param name="context">The per-operation exchange context carrying the outbound-fetch policy evaluated before a by-reference GET.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The recreated Credential Offer, or the <see cref="FetchCredentialOfferAsync"/> failure when
    /// the link is by reference and the GET was refused or malformed.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="deepLink"/> carries both <c>credential_offer</c> and <c>credential_offer_uri</c>.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the link is by reference but the configuration has no
    /// <see cref="Oid4VciWalletConfiguration.FetchCredentialOffer"/> transport, or when the link is
    /// by value but its inline offer JSON does not parse.
    /// </exception>
    public async ValueTask<Result<CredentialOffer, Oid4VciRequestFailure>> AcceptCredentialOfferAsync(
        string deepLink,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(deepLink);
        ArgumentNullException.ThrowIfNull(context);

        //§4.1: a link carries either credential_offer_uri (by reference) or credential_offer (by
        //value), never both — TryGetCredentialOfferUri rejects the mutual-exclusion violation.
        if(CredentialOfferSerializer.TryGetCredentialOfferUri(deepLink, out Uri? credentialOfferUri))
        {
            return await FetchCredentialOfferAsync(credentialOfferUri!, context, cancellationToken).ConfigureAwait(false);
        }

        //§4.1.2: the by-value link (or raw credential_offer value) carries the offer JSON inline;
        //a caller-supplied value that does not parse is the caller's own malformed input, not a
        //remote refusal, so it raises rather than answering a failure value.
        return Result<CredentialOffer, Oid4VciRequestFailure>.Success(
            CredentialOfferSerializer.ExtractFromDeepLink(deepLink));
    }


    /// <summary>
    /// GETs the §4.1.3 by-reference Credential Offer at <paramref name="credentialOfferUri"/>
    /// through the library's guarded <see cref="OutboundFetch"/> chokepoint and parses the returned
    /// offer JSON. §4.1.3: "Upon receipt of the credential_offer_uri, the Wallet MUST send an HTTP
    /// GET request to the URI to retrieve the referenced Credential Offer Object ... and parse it
    /// to recreate the Credential Offer parameters." Follows the same fetch-validate shape
    /// <see cref="Client.AuthorizationServerMetadataDocuments.ResolveAsync"/> applies to its own
    /// document fetch: a transport hint plus an authoritative post-read size check, an exact
    /// <c>200</c> status, and a media-type gate — so <see cref="OutboundFetch.FetchAsync"/>'s own
    /// redirect re-validation and per-hop policy evaluation cover this GET exactly as they cover
    /// that resolver's.
    /// </summary>
    /// <param name="credentialOfferUri">The <c>credential_offer_uri</c> to retrieve.</param>
    /// <param name="context">
    /// The per-operation exchange context. An <see cref="OutboundFetchPolicy"/> set on it directly
    /// (<see cref="OutboundFetchPolicyExchangeContextExtensions.SetOutboundFetchPolicy"/>) wins;
    /// otherwise <see cref="Oid4VciWalletConfiguration.OutboundFetchPolicy"/> is the deployment
    /// default applied — the same resolution order every other dial this Wallet makes uses.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The recreated Credential Offer, or a failure: <see cref="Oid4VciRequestFailureKind.OutboundPolicyDenied"/>
    /// when the policy refused <paramref name="credentialOfferUri"/> or a redirect hop, or refused
    /// to follow the redirect at all; <see cref="Oid4VciRequestFailureKind.ErrorResponse"/> for a
    /// non-<c>200</c> status (§4.1.3 defines no error body for this GET, so <see cref="Oid4VciRequestFailure.ErrorCode"/>
    /// is always <see langword="null"/>); <see cref="Oid4VciRequestFailureKind.MalformedResponse"/>
    /// when the content type is not <c>application/json</c>, the body exceeds
    /// <see cref="Oid4VciWalletConfiguration.MaximumCredentialOfferBytes"/>, or the body does not
    /// satisfy §4.1.1's <c>credential_issuer</c> and <c>credential_configuration_ids</c> rules —
    /// the same rules <see cref="CredentialOfferSerializer.FromJson"/> raises for a caller-supplied
    /// offer, answered here as a value since the body is the Issuer's own.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no <see cref="Oid4VciWalletConfiguration.FetchCredentialOffer"/> transport is configured.
    /// </exception>
    public async ValueTask<Result<CredentialOffer, Oid4VciRequestFailure>> FetchCredentialOfferAsync(
        Uri credentialOfferUri,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credentialOfferUri);
        ArgumentNullException.ThrowIfNull(context);

        if(Configuration.FetchCredentialOffer is null)
        {
            throw new InvalidOperationException(
                "§4.1.3 the Wallet MUST send an HTTP GET to the credential_offer_uri to retrieve the "
                + "offer, but the wallet configuration has no FetchCredentialOffer transport. Wire "
                + "Oid4VciWalletConfiguration.FetchCredentialOffer to fetch a by-reference offer.");
        }

        //The call's ExchangeContext override wins; Configuration.OutboundFetchPolicy is the
        //deployment default otherwise — resolved once and propagated onto context so
        //OutboundFetch.FetchAsync's own policy read (every hop, including redirects) sees it.
        context.SetOutboundFetchPolicy(context.ResolveOutboundFetchPolicy(Configuration.OutboundFetchPolicy));

        OutboundRequest request = new()
        {
            Target = credentialOfferUri,
            Method = "GET",
            MaxResponseBytes = Configuration.MaximumCredentialOfferBytes
        };

        //A transport exception propagates as itself; the guarded fetch chokepoint answers policy
        //and redirect refusals as OutboundFetchResult values, not exceptions.
        OutboundFetchResult fetch = await OutboundFetch.FetchAsync(
            request, context, Configuration.FetchCredentialOffer, cancellationToken).ConfigureAwait(false);

        if(!fetch.IsFetched || fetch.Response is null)
        {
            return Result<CredentialOffer, Oid4VciRequestFailure>.Failure(
                OutboundFetchOutcomeFailure(credentialOfferUri, fetch.Outcome, fetch.DenyReason));
        }

        OutboundResponse response = fetch.Response;

        //Non-normative example aside, the only documented success status is the implicit 200 a JSON
        //body GET answers with; mirrors AuthorizationServerMetadataDocuments.ResolveAsync's own
        //exact-200 gate rather than accepting the wider 2xx range. §4.1.3 defines no error body for
        //this GET, so a non-200 status carries no wire error code or description.
        if(response.StatusCode != 200)
        {
            return Result<CredentialOffer, Oid4VciRequestFailure>.Failure(new Oid4VciRequestFailure
            {
                Kind = Oid4VciRequestFailureKind.ErrorResponse,
                Endpoint = credentialOfferUri,
                StatusCode = response.StatusCode,
                ErrorCode = null,
                ErrorDescription = null
            });
        }

        //§4.1.3: "The response from the Credential Issuer that contains a Credential Offer Object
        //MUST use the media type application/json."
        _ = response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType);
        if(!IsJsonContentType(contentType))
        {
            return Result<CredentialOffer, Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(
                    credentialOfferUri,
                    response.StatusCode,
                    $"§4.1.3 the response content type was '{contentType}', not application/json."));
        }

        //The authoritative post-read size check — MaxResponseBytes above is only a transport hint a
        //hostile or non-conforming transport may not honor.
        if(response.Body.Length > Configuration.MaximumCredentialOfferBytes)
        {
            return Result<CredentialOffer, Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(
                    credentialOfferUri,
                    response.StatusCode,
                    "§4.1.3 the response exceeded the configured maximum size."));
        }

        //The offer body is remote input, so a malformed parse answers MalformedResponse rather
        //than raising — CredentialOfferSerializer.TryParse shares §4.1.1's rules with FromJson,
        //which raises them for the by-value link's caller-supplied JSON instead.
        string offerJson = Encoding.UTF8.GetString(response.Body.Span);
        if(!CredentialOfferSerializer.TryParse(offerJson, out CredentialOffer? offer, out string? violatedRule))
        {
            return Result<CredentialOffer, Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(credentialOfferUri, response.StatusCode, violatedRule!));
        }

        return Result<CredentialOffer, Oid4VciRequestFailure>.Success(offer!);
    }


    /// <summary>
    /// Whether <paramref name="contentType"/> is exactly <c>application/json</c> per §4.1.3, with
    /// parameters (e.g. <c>;charset=utf-8</c>) stripped before comparison.
    /// </summary>
    private static bool IsJsonContentType(string? contentType)
    {
        return ContentTypeReader.ReadMediaType(contentType).Equals(
            WellKnownMediaTypes.Application.Json, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// Drives the Pre-Authorized Code issuance flow end-to-end from a §4
    /// <see cref="CredentialOffer"/> and returns the issued Credential string.
    /// The offer MUST carry a <see cref="CredentialOffer.PreAuthorizedCodeGrant"/>.
    /// </summary>
    /// <param name="offer">The Credential Offer the Wallet "scanned".</param>
    /// <param name="credentialConfigurationId">
    /// The Credential Configuration the Wallet asks for (one of the offer's ids). The Credential Request
    /// names the first <c>credential_identifiers</c> value the Token Response granted for this
    /// configuration, or this configuration when the response returned no <c>openid_credential</c> object.
    /// </param>
    /// <param name="holderPrivate">The holder's signing private key for the §7.2.1 proof.</param>
    /// <param name="holderPublic">The holder's public key projected into the proof header.</param>
    /// <param name="endpoints">The resolved Token / Nonce / Credential endpoint URLs (§12.2 metadata in deployments).</param>
    /// <param name="transactionCode">The §6.1 <c>tx_code</c>, or <see langword="null"/> when none is required.</param>
    /// <param name="responseEncryption">The §8.2 <c>credential_response_encryption</c> ask, or <see langword="null"/> for a plaintext response.</param>
    /// <param name="context">The per-operation exchange context carrying the outbound-fetch policy evaluated before each dial.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The issued Credential string (the section 8.3 <c>credentials[0].credential</c>), or the endpoint's refusal;
    /// or a <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> failure, with no Credential Request
    /// sent, when the Token Response granted <c>credential_identifiers</c> for other configurations only
    /// or carries malformed <c>authorization_details</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="offer"/> carries no Pre-Authorized Code grant, or when the
    /// issuance succeeded on the wire but was deferred or carried no Credential — the simple
    /// overload cannot describe either, so the caller's programming error surfaces as an
    /// exception rather than the endpoint's own <see cref="Oid4VciRequestFailure"/>.
    /// </exception>
    public async ValueTask<Result<string, Oid4VciRequestFailure>> IssuePreAuthorizedAsync(
        CredentialOffer offer,
        string credentialConfigurationId,
        PrivateKeyMemory holderPrivate,
        PublicKeyMemory holderPublic,
        Oid4VciIssuanceEndpoints endpoints,
        string? transactionCode,
        CredentialResponseEncryption? responseEncryption,
        ExchangeContext context,
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
            context,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives the Pre-Authorized Code issuance flow from a §4 <see cref="CredentialOffer"/> and returns
    /// the full §8.3 outcome (every batch Credential, the §11 <c>notification_id</c>, or a §9 deferral).
    /// The offer MUST carry a <see cref="CredentialOffer.PreAuthorizedCodeGrant"/>.
    /// </summary>
    /// <param name="offer">The Credential Offer the Wallet "scanned".</param>
    /// <param name="credentialConfigurationId">
    /// The Credential Configuration the Wallet asks for (one of the offer's ids). The Credential Request
    /// names the first <c>credential_identifiers</c> value the Token Response granted for this
    /// configuration, or this configuration when the response returned no <c>openid_credential</c> object.
    /// </param>
    /// <param name="holderPrivate">The holder's signing private key for the §7.2.1 proof.</param>
    /// <param name="holderPublic">The holder's public key projected into the proof header.</param>
    /// <param name="endpoints">The resolved Token / Nonce / Credential endpoint URLs.</param>
    /// <param name="transactionCode">The §6.1 <c>tx_code</c>, or <see langword="null"/> when none is required.</param>
    /// <param name="responseEncryption">The §8.2 <c>credential_response_encryption</c> ask, or <see langword="null"/>.</param>
    /// <param name="context">The per-operation exchange context carrying the outbound-fetch policy evaluated before each dial.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The full Credential Response outcome, or the endpoint's refusal; or a
    /// <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> failure, with no Credential Request
    /// sent, when the Token Response granted <c>credential_identifiers</c> for other configurations only
    /// or carries malformed <c>authorization_details</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// </returns>
    /// <exception cref="InvalidOperationException">Thrown when <paramref name="offer"/> carries no Pre-Authorized Code grant.</exception>
    public async ValueTask<Result<CredentialIssuanceResult, Oid4VciRequestFailure>> IssuePreAuthorizedDetailedAsync(
        CredentialOffer offer,
        string credentialConfigurationId,
        PrivateKeyMemory holderPrivate,
        PublicKeyMemory holderPublic,
        Oid4VciIssuanceEndpoints endpoints,
        string? transactionCode,
        CredentialResponseEncryption? responseEncryption,
        ExchangeContext context,
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
            context,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives the Pre-Authorized Code issuance flow from an already-parsed grant
    /// and the Credential Issuer identifier (the proof <c>aud</c>), returning the
    /// issued Credential string.
    /// </summary>
    /// <param name="grant">The offer's Pre-Authorized Code grant carrying the <c>pre-authorized_code</c>.</param>
    /// <param name="credentialIssuer">The Credential Issuer identifier — the holder proof's <c>aud</c>.</param>
    /// <param name="credentialConfigurationId">
    /// The Credential Configuration the Wallet asks for. The Credential Request names the first
    /// <c>credential_identifiers</c> value the Token Response granted for this configuration, or this
    /// configuration when the response returned no <c>openid_credential</c> object.
    /// </param>
    /// <param name="holderPrivate">The holder's signing private key for the §7.2.1 proof.</param>
    /// <param name="holderPublic">The holder's public key projected into the proof header.</param>
    /// <param name="endpoints">The resolved Token / Nonce / Credential endpoint URLs.</param>
    /// <param name="transactionCode">The §6.1 <c>tx_code</c>, or <see langword="null"/>.</param>
    /// <param name="responseEncryption">The §8.2 response-encryption ask, or <see langword="null"/>.</param>
    /// <param name="context">The per-operation exchange context carrying the outbound-fetch policy evaluated before each dial.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The issued Credential string (the section 8.3 <c>credentials[0].credential</c>), or the endpoint's refusal;
    /// or a <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> failure, with no Credential Request
    /// sent, when the Token Response granted <c>credential_identifiers</c> for other configurations only
    /// or carries malformed <c>authorization_details</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the issuance succeeded on the wire but was deferred or produced no
    /// Credential — use
    /// <see cref="IssuePreAuthorizedDetailedAsync(PreAuthorizedCodeOfferGrant, Uri, string, PrivateKeyMemory, PublicKeyMemory, Oid4VciIssuanceEndpoints, string?, CredentialResponseEncryption?, ExchangeContext, CancellationToken)"/>
    /// to handle a §9 deferral, a §8.2 batch, or the §11 <c>notification_id</c>.
    /// </exception>
    public async ValueTask<Result<string, Oid4VciRequestFailure>> IssuePreAuthorizedAsync(
        PreAuthorizedCodeOfferGrant grant,
        Uri credentialIssuer,
        string credentialConfigurationId,
        PrivateKeyMemory holderPrivate,
        PublicKeyMemory holderPublic,
        Oid4VciIssuanceEndpoints endpoints,
        string? transactionCode,
        CredentialResponseEncryption? responseEncryption,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssuePreAuthorizedDetailedAsync(
            grant,
            credentialIssuer,
            credentialConfigurationId,
            holderPrivate,
            holderPublic,
            endpoints,
            transactionCode,
            responseEncryption,
            context,
            cancellationToken).ConfigureAwait(false);

        if(!outcome.IsSuccess)
        {
            return Result<string, Oid4VciRequestFailure>.Failure(outcome.Error);
        }

        CredentialIssuanceResult result = outcome.Value;

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

        return Result<string, Oid4VciRequestFailure>.Success(result.Credentials[0]);
    }


    /// <summary>
    /// Drives the Pre-Authorized Code issuance flow from an already-parsed grant and the Credential
    /// Issuer identifier (the proof <c>aud</c>), returning the full §8.3 outcome: every issued
    /// Credential of a §8.2 batch, the §11 <c>notification_id</c>, or a §9 deferral's
    /// <c>transaction_id</c>.
    /// </summary>
    /// <param name="grant">The offer's Pre-Authorized Code grant carrying the <c>pre-authorized_code</c>.</param>
    /// <param name="credentialIssuer">The Credential Issuer identifier — the holder proof's <c>aud</c>.</param>
    /// <param name="credentialConfigurationId">
    /// The Credential Configuration the Wallet asks for. The Credential Request names the first
    /// <c>credential_identifiers</c> value the Token Response granted for this configuration, or this
    /// configuration when the response returned no <c>openid_credential</c> object.
    /// </param>
    /// <param name="holderPrivate">The holder's signing private key for the §7.2.1 proof.</param>
    /// <param name="holderPublic">The holder's public key projected into the proof header.</param>
    /// <param name="endpoints">The resolved Token / Nonce / Credential endpoint URLs.</param>
    /// <param name="transactionCode">The §6.1 <c>tx_code</c>, or <see langword="null"/>.</param>
    /// <param name="responseEncryption">The §8.2 response-encryption ask, or <see langword="null"/>.</param>
    /// <param name="context">The per-operation exchange context carrying the outbound-fetch policy evaluated before each dial.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The full Credential Response outcome, or the endpoint's refusal; or a
    /// <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> failure, with no Credential Request
    /// sent, when the Token Response granted <c>credential_identifiers</c> for other configurations only
    /// or carries malformed <c>authorization_details</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// </returns>
    public async ValueTask<Result<CredentialIssuanceResult, Oid4VciRequestFailure>> IssuePreAuthorizedDetailedAsync(
        PreAuthorizedCodeOfferGrant grant,
        Uri credentialIssuer,
        string credentialConfigurationId,
        PrivateKeyMemory holderPrivate,
        PublicKeyMemory holderPublic,
        Oid4VciIssuanceEndpoints endpoints,
        string? transactionCode,
        CredentialResponseEncryption? responseEncryption,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(credentialIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialConfigurationId);
        ArgumentNullException.ThrowIfNull(holderPrivate);
        ArgumentNullException.ThrowIfNull(holderPublic);
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(context);

        //§6: the Pre-Authorized Code grant mints the access token over an HTTP
        //form POST. tx_code rides alongside when the offer required one. The Token Response's
        //granted credential_identifiers decide what the Credential Request names (section 6.2).
        Result<(string AccessToken, string TokenType, DateTimeOffset? ExpiresAt, CredentialRequestTarget Target), Oid4VciRequestFailure> tokenOutcome =
            await RequestAccessTokenAsync(
                grant.PreAuthorizedCode, transactionCode, credentialConfigurationId, endpoints.TokenEndpoint, context, cancellationToken)
                .ConfigureAwait(false);

        if(!tokenOutcome.IsSuccess)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(tokenOutcome.Error);
        }

        (string accessToken, string tokenType, DateTimeOffset? accessTokenExpiresAt, CredentialRequestTarget target) = tokenOutcome.Value;

        return await IssueWithAccessTokenDetailedAsync(
            accessToken,
            tokenType,
            accessTokenExpiresAt,
            credentialIssuer,
            target,
            holderPrivate,
            holderPublic,
            endpoints,
            responseEncryption,
            context,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives issuance from an access token the Wallet already holds - the section 7 Nonce Request,
    /// the section 7.2.1 holder key proof, and the section 8 Credential Request - returning the full
    /// section 8.3 outcome. This is the grant-agnostic half of issuance: the Pre-Authorized Code path
    /// obtains its token in this client and continues here, while the Authorization Code grant
    /// (HAIP: RFC 9126 pushed authorization with RFC 7636 PKCE) obtains its token through the
    /// authorization-code client - carrying the section 5.1.1 <c>authorization_details</c> composed
    /// by <see cref="CredentialAuthorizationDetailComposition"/> and the offer's
    /// <c>issuer_state</c> on the authorization request - and hands the token here.
    /// </summary>
    /// <remarks>
    /// The caller names what the Credential Request asks for through <paramref name="target"/>: when
    /// the Token Response returned <c>credential_identifiers</c> in its <c>authorization_details</c>,
    /// <see cref="CredentialRequestTarget.ForIdentifier"/> with one of them; otherwise
    /// <see cref="CredentialRequestTarget.ForConfiguration"/>. The request body names exactly that
    /// member. The Pre-Authorized Code entry points read their own Token Response and choose the
    /// target themselves.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// </remarks>
    /// <param name="accessToken">The access token authorizing the Nonce and Credential Requests.</param>
    /// <param name="tokenType">The token's <c>token_type</c> (<c>Bearer</c>, or <c>DPoP</c> with the DPoP delegate wired).</param>
    /// <param name="accessTokenExpiresAt">
    /// The instant <paramref name="accessToken"/> expires, carried over into the returned
    /// <see cref="CredentialIssuanceResult.ExpiresAt"/>, or <see langword="null"/> when the caller
    /// does not know it (the section 6 token response carried no <c>expires_in</c>, or the token
    /// came from a grant this client did not itself redeem).
    /// </param>
    /// <param name="credentialIssuer">The Credential Issuer identifier - the holder proof's <c>aud</c>.</param>
    /// <param name="target">What the Credential Request names: the configuration, or an identifier the Token Response granted.</param>
    /// <param name="holderPrivate">The holder's signing private key for the section 7.2.1 proof.</param>
    /// <param name="holderPublic">The holder's public key projected into the proof header.</param>
    /// <param name="endpoints">The resolved Nonce / Credential endpoint URLs.</param>
    /// <param name="responseEncryption">The section 8.2 response-encryption ask, or <see langword="null"/>.</param>
    /// <param name="context">The per-operation exchange context carrying the outbound-fetch policy evaluated before each dial.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The full Credential Response outcome, or the endpoint's refusal.</returns>
    public async ValueTask<Result<CredentialIssuanceResult, Oid4VciRequestFailure>> IssueWithAccessTokenDetailedAsync(
        string accessToken,
        string tokenType,
        DateTimeOffset? accessTokenExpiresAt,
        Uri credentialIssuer,
        CredentialRequestTarget target,
        PrivateKeyMemory holderPrivate,
        PublicKeyMemory holderPublic,
        Oid4VciIssuanceEndpoints endpoints,
        CredentialResponseEncryption? responseEncryption,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenType);
        ArgumentNullException.ThrowIfNull(credentialIssuer);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(holderPrivate);
        ArgumentNullException.ThrowIfNull(holderPublic);
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(context);

        //§7: the Nonce Endpoint issues the c_nonce the proof must carry.
        Result<string, Oid4VciRequestFailure> nonceOutcome = await RequestNonceAsync(
            accessToken, tokenType, endpoints.NonceEndpoint, context, cancellationToken).ConfigureAwait(false);

        if(!nonceOutcome.IsSuccess)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(nonceOutcome.Error);
        }

        string credentialNonce = nonceOutcome.Value;

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
            accessTokenExpiresAt,
            target,
            proofJwt,
            responseEncryption,
            endpoints.CredentialEndpoint,
            context,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends the <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1.1">§6.1.1</see>
    /// Pre-Authorized Code Token Request — <c>grant_type=...pre-authorized_code</c>, the code, and
    /// (when required) <c>tx_code</c> as form fields — attaching a
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see> DPoP proof
    /// when <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/> is wired ("This is
    /// applicable for all access token requests regardless of grant type"), and parses
    /// <c>access_token</c>, <c>token_type</c>, and <c>expires_in</c> off the JSON Token Response.
    /// <c>expires_in</c> is added to the instant this method sends the request rather than the
    /// instant it reads the response:
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see> counts
    /// it "from the time the response was generated," and the request instant is never later than
    /// that, so the computed expiry never overstates the token's remaining lifetime.
    /// </summary>
    /// <remarks>
    /// The Token Response's <c>authorization_details</c> are read with the span reader too
    /// (<see cref="ReadGrantedIdentifier"/>), and the answer keeps what they grant with the token as
    /// the target of the Credential Request: the first <c>credential_identifiers</c> value of the
    /// <c>openid_credential</c> object naming <paramref name="credentialConfigurationId"/>, or the
    /// configuration itself when the response returned no <c>openid_credential</c> object.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// </remarks>
    /// <returns>
    /// The access token, its type, its computed expiry and the Credential Request's target; or a failure:
    /// <see cref="Oid4VciRequestFailureKind.OutboundPolicyDenied"/> when the policy refused
    /// <paramref name="tokenEndpoint"/> before any dial, <see cref="Oid4VciRequestFailureKind.ErrorResponse"/>
    /// for the RFC 6749 §5.2 Token Error Response a non-2xx status carries, or
    /// <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> when the success body is not
    /// well-formed JSON, repeats a member, carries no <c>access_token</c>, carries
    /// <c>authorization_details</c> that are not a non-empty array of objects, an entry without a
    /// string <c>type</c>, or an <c>openid_credential</c> object without its configuration or a non-empty <c>credential_identifiers</c> or listing an
    /// identifier that is empty or white space, or grants <c>credential_identifiers</c> for no object
    /// naming <paramref name="credentialConfigurationId"/>.
    /// </returns>
    private async ValueTask<Result<(string AccessToken, string TokenType, DateTimeOffset? ExpiresAt, CredentialRequestTarget Target), Oid4VciRequestFailure>> RequestAccessTokenAsync(
        string preAuthorizedCode,
        string? transactionCode,
        string credentialConfigurationId,
        Uri tokenEndpoint,
        ExchangeContext context,
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

        Oid4VciRequestFailure? policyDenial = EvaluateOutboundPolicy(tokenEndpoint, context, Configuration.OutboundFetchPolicy);
        if(policyDenial is not null)
        {
            return Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(policyDenial);
        }

        DateTimeOffset requestedAt = Configuration.TimeProvider.GetUtcNow();
        HttpResponseData response = await SendTokenRequestAsync(
            formFields, tokenEndpoint, context, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode is < 200 or >= 300)
        {
            return Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(
                ParseErrorResponse(response.StatusCode, response.Body, tokenEndpoint));
        }

        ReadOnlySpan<byte> tokenJson = Encoding.UTF8.GetBytes(response.Body);

        //RFC 7519-style §4 uniqueness posture applied to a fetched JSON document: a repeated
        //"access_token" would let this reader select the first occurrence while the Authorization
        //Server's own semantics — and any other consumer of the same body — resolve the last.
        if(!JwkJsonReader.IsWellFormedJsonDocument(tokenJson))
        {
            return Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(
                    tokenEndpoint,
                    response.StatusCode,
                    "§6 the Token Response is not well-formed JSON, or contains a duplicate member name."));
        }

        string? accessToken = JwkJsonReader.ExtractStringValue(tokenJson, WellKnownTokenTypes.AccessTokenUtf8);
        if(accessToken is null)
        {
            return Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(tokenEndpoint, response.StatusCode, "§6 the Token Response carried no access_token."));
        }

        //RFC 6749 §5.1 token_type defaults to Bearer when the AS omits it.
        string tokenType = JwkJsonReader.ExtractStringValue(tokenJson, OAuthRequestParameterNames.TokenTypeUtf8)
            ?? WellKnownAuthenticationSchemes.Bearer;

        DateTimeOffset? expiresAt = JwkJsonReader.TryExtractLongValue(
            tokenJson, OAuthRequestParameterNames.ExpiresInUtf8, out long expiresInSeconds)
            ? requestedAt.AddSeconds(expiresInSeconds)
            : null;

        //Section 6.2: the openid_credential objects the response returned name the identifiers the
        //Credential Request must use; without them the request names the configuration.
        GrantedIdentifierReading reading = ReadGrantedIdentifier(
            tokenJson, credentialConfigurationId, out string? grantedIdentifier);

        return reading switch
        {
            GrantedIdentifierReading.NoCredentialDetails =>
                Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Success(
                    (accessToken, tokenType, expiresAt, CredentialRequestTarget.ForConfiguration(credentialConfigurationId))),
            GrantedIdentifierReading.Granted =>
                Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Success(
                    (accessToken, tokenType, expiresAt, CredentialRequestTarget.ForIdentifier(grantedIdentifier!))),
            GrantedIdentifierReading.NotGrantedForConfiguration =>
                Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(
                    MalformedResponseFailure(
                        tokenEndpoint,
                        response.StatusCode,
                        "Section 6.2 the Token Response returned credential_identifiers for no openid_credential object "
                        + "naming the requested credential_configuration_id.")),
            _ =>
                Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(
                    MalformedResponseFailure(
                        tokenEndpoint,
                        response.StatusCode,
                        "Section 6.2 the Token Response's authorization_details are not a non-empty array of objects, "
                        + "an entry lacks a string type, or an "
                        + "openid_credential object lacks its credential_configuration_id or a non-empty "
                        + "credential_identifiers, or lists an identifier that is empty or white space."))
        };
    }


    /// <summary>
    /// What <see cref="ReadGrantedIdentifier"/> found in a Token Response's
    /// <c>authorization_details</c>.
    /// </summary>
    private enum GrantedIdentifierReading
    {
        /// <summary>The response returned no <c>openid_credential</c> object; the request names the configuration.</summary>
        NoCredentialDetails,

        /// <summary>An <c>openid_credential</c> object names the requested configuration and grants identifiers.</summary>
        Granted,

        /// <summary><c>openid_credential</c> objects were returned, none naming the requested configuration.</summary>
        NotGrantedForConfiguration,

        /// <summary>
        /// The member is not a non-empty array of objects, an entry lacks <c>type</c> or carries a
        /// <c>type</c> that is not a JSON string, or an <c>openid_credential</c> object misses a REQUIRED
        /// member or lists an identifier that is empty or white space.
        /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
        /// "It is a non-empty array of objects, as defined in Section 7 of [RFC9396]."
        /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>:
        /// "type: An identifier for the authorization details type as a string. The value of the type
        /// field determines the allowable contents of the object that contains it. The value is unique
        /// for the described API in the context of the AS. This field is REQUIRED."
        /// </summary>
        Malformed
    }


    /// <summary>
    /// Reads a Token Response's RFC 9396 <c>authorization_details</c> with the span reader, the
    /// fixed-shape wire JSON the Authorization Server returns for <c>openid_credential</c> grants
    /// (<c>type</c>, <c>credential_configuration_id</c>, <c>credential_identifiers</c>), and finds the
    /// first identifier granted for <paramref name="credentialConfigurationId"/>. Objects whose
    /// <c>type</c> is a string other than <c>openid_credential</c> are skipped. The whole array is
    /// validated before a grant is answered: an empty array, an entry that is not an object, an entry
    /// whose <c>type</c> is absent or not a JSON string, or an <c>openid_credential</c> object without
    /// its configuration, without a non-empty <c>credential_identifiers</c>, or listing an identifier
    /// that is empty or white space (which names no Credential Dataset), makes the member malformed
    /// wherever it stands. <see cref="JwkJsonReader.ExtractStringValue"/> answers
    /// <see langword="null"/> for a <c>type</c> that is absent or not a string and the value for a
    /// string, which tells the two cases apart. The document is the one
    /// <see cref="JwkJsonReader.IsWellFormedJsonDocument"/> accepted.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "It is a non-empty array of objects, as defined in Section 7 of [RFC9396]." And:
    /// "credential_identifiers: REQUIRED. A non-empty array of strings, each uniquely identifying a
    /// Credential Dataset that can be issued using the Access Token returned in this response."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>:
    /// "type: An identifier for the authorization details type as a string. The value of the type
    /// field determines the allowable contents of the object that contains it. The value is unique for
    /// the described API in the context of the AS. This field is REQUIRED."
    /// </summary>
    /// <param name="tokenJson">The well-formed Token Response body.</param>
    /// <param name="credentialConfigurationId">The configuration the Wallet requests.</param>
    /// <param name="grantedIdentifier">The first identifier granted for the configuration, when <see cref="GrantedIdentifierReading.Granted"/>.</param>
    /// <returns>What the member holds for the requested configuration.</returns>
    private static GrantedIdentifierReading ReadGrantedIdentifier(
        ReadOnlySpan<byte> tokenJson, string credentialConfigurationId, out string? grantedIdentifier)
    {
        grantedIdentifier = null;
        ReadOnlySpan<byte> detailsKey = OAuthRequestParameterNames.AuthorizationDetailsUtf8;
        int keyStart = JwkJsonReader.IndexOfKey(tokenJson, detailsKey);
        if(keyStart < 0)
        {
            return GrantedIdentifierReading.NoCredentialDetails;
        }

        int position = JwkJsonReader.SkipWhitespaceAndColon(tokenJson, keyStart + detailsKey.Length + 1);
        if(position < 0 || position >= tokenJson.Length || tokenJson[position] != (byte)'[')
        {
            return GrantedIdentifierReading.Malformed;
        }

        bool hasEntry = false;
        bool hasCredentialDetail = false;
        string? firstGrantedIdentifier = null;
        position++;
        while(true)
        {
            while(position < tokenJson.Length && IsArraySeparator(tokenJson[position]))
            {
                position++;
            }

            if(position >= tokenJson.Length)
            {
                return GrantedIdentifierReading.Malformed;
            }

            if(tokenJson[position] == (byte)']')
            {
                grantedIdentifier = firstGrantedIdentifier;

                //Section 6.2: the member is a non-empty array, so an array that closes without an
                //entry is malformed rather than an absence of details.
                return (hasEntry, firstGrantedIdentifier, hasCredentialDetail) switch
                {
                    (false, _, _) => GrantedIdentifierReading.Malformed,
                    (true, not null, _) => GrantedIdentifierReading.Granted,
                    (true, null, true) => GrantedIdentifierReading.NotGrantedForConfiguration,
                    (_, _, false) => GrantedIdentifierReading.NoCredentialDetails
                };
            }

            int objectEnd = tokenJson[position] == (byte)'{' ? FindObjectEnd(tokenJson, position) : -1;
            if(objectEnd < 0)
            {
                return GrantedIdentifierReading.Malformed;
            }

            ReadOnlySpan<byte> detail = tokenJson[position..objectEnd];
            position = objectEnd;
            hasEntry = true;

            //RFC 9396 Section 2: every entry carries type as a string. The reader answers null for a
            //type that is absent or not a JSON string (a number, null, an object or an array), which
            //makes the member malformed wherever the entry stands; a string of another type is an
            //entry for another API and is skipped.
            string? type = JwkJsonReader.ExtractStringValue(detail, AuthorizationDetailsParameterNames.TypeUtf8);
            if(type is null)
            {
                return GrantedIdentifierReading.Malformed;
            }

            if(!string.Equals(type, AuthorizationDetailsTypeValues.OpenIdCredential, StringComparison.Ordinal))
            {
                continue;
            }

            hasCredentialDetail = true;
            string? configurationId = JwkJsonReader.ExtractStringValue(
                detail, Oid4VciCredentialParameterNames.CredentialConfigurationIdUtf8);
            List<string>? identifiers = JwkJsonReader.ExtractStringArrayProperty(
                detail, Oid4VciCredentialParameterNames.CredentialIdentifiersUtf8);
            if(configurationId is null
                || identifiers is not { Count: > 0 }
                || identifiers.Exists(string.IsNullOrWhiteSpace))
            {
                return GrantedIdentifierReading.Malformed;
            }

            if(firstGrantedIdentifier is null
                && string.Equals(configurationId, credentialConfigurationId, StringComparison.Ordinal))
            {
                firstGrantedIdentifier = identifiers[0];
            }
        }
    }


    /// <summary>Whether <paramref name="value"/> is JSON whitespace or the comma between array elements.</summary>
    /// <param name="value">The byte read between array elements.</param>
    /// <returns><see langword="true"/> for a space, tab, carriage return, line feed or comma.</returns>
    private static bool IsArraySeparator(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or (byte)',';


    /// <summary>
    /// Finds the end of the JSON object starting at <paramref name="start"/>: the index after its
    /// closing brace, counting nested objects and arrays and skipping string contents, escapes
    /// included, so a brace inside a string does not end the object.
    /// </summary>
    /// <param name="json">The JSON text.</param>
    /// <param name="start">The index of the object's opening brace.</param>
    /// <returns>The index after the closing brace, or -1 when the object does not close.</returns>
    private static int FindObjectEnd(ReadOnlySpan<byte> json, int start)
    {
        int depth = 0;
        for(int position = start; position < json.Length; position++)
        {
            byte current = json[position];
            if(current == (byte)'"')
            {
                position++;
                while(position < json.Length && json[position] != (byte)'"')
                {
                    if(json[position] == (byte)'\\')
                    {
                        position++;
                    }

                    position++;
                }

                continue;
            }

            depth += current switch
            {
                (byte)'{' or (byte)'[' => 1,
                (byte)'}' or (byte)']' => -1,
                _ => 0
            };

            if(depth == 0)
            {
                return position + 1;
            }
        }

        return -1;
    }


    /// <summary>
    /// Sends the §6 Token Request once when <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>
    /// carries no DPoP key, or through <see cref="DpopNonceRetry.SendWithNonceRetryAsync"/> — the
    /// helper shared with the AuthCode token endpoint's own retry — when it does, embedding a fresh
    /// proof on every attempt and retrying exactly once on an RFC 9449 §8.1 <c>use_dpop_nonce</c>
    /// challenge (HTTP 400 + <c>error=use_dpop_nonce</c> in the JSON body + a <c>DPoP-Nonce</c>
    /// response header).
    /// </summary>
    private async ValueTask<HttpResponseData> SendTokenRequestAsync(
        IReadOnlyDictionary<string, string> formFields,
        Uri tokenEndpoint,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(Configuration.ConstructDpopProofAsync is null || Configuration.DpopKey is null)
        {
            return await Configuration.SendFormPost(
                tokenEndpoint, formFields, OutgoingHeaders.Empty, context, cancellationToken).ConfigureAwait(false);
        }

        string authority = InMemoryDpopNonceCache.AuthorityFor(tokenEndpoint);

        return await DpopNonceRetry.SendWithNonceRetryAsync(
            (nonce, ct) => SendFormPostWithDpopAsync(formFields, tokenEndpoint, nonce, context, ct),
            static candidate => candidate.StatusCode == 400
                && candidate.Body.Contains(OAuthErrors.UseDpopNonce, StringComparison.Ordinal),
            authority,
            Configuration.LookupDpopNonce,
            Configuration.StoreDpopNonce,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints one fresh DPoP proof bound to <paramref name="tokenEndpoint"/> — embedding
    /// <paramref name="nonce"/> when supplied — and sends the §6 Token Request once. No <c>ath</c>
    /// claim: the token endpoint proof is minted before an access token exists to bind to.
    /// </summary>
    private async ValueTask<HttpResponseData> SendFormPostWithDpopAsync(
        IReadOnlyDictionary<string, string> formFields,
        Uri tokenEndpoint,
        string? nonce,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        string jti = await Configuration.GenerateIdentifierAsync!(
            WellKnownIdentifierPurposes.OAuthJti, context, cancellationToken).ConfigureAwait(false);

        DpopProofClaims claims = new()
        {
            Htm = HttpPostMethod,
            Htu = tokenEndpoint.GetLeftPart(UriPartial.Path),
            Iat = Configuration.TimeProvider.GetUtcNow(),
            Jti = jti,
            Nonce = nonce
        };

        string proof = await Configuration.ConstructDpopProofAsync!(
            claims, Configuration.DpopKey!, cancellationToken).ConfigureAwait(false);

        OutgoingHeaders headers = OutgoingHeaders.Empty.WithDpop(proof);

        return await Configuration.SendFormPost(
            tokenEndpoint, formFields, headers, context, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends the <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.1">§7.1</see>
    /// Nonce Request — an authorized POST with no body — and reads <c>c_nonce</c> off the JSON Nonce
    /// Response.
    /// </summary>
    /// <returns>
    /// The <c>c_nonce</c>; or a failure: <see cref="Oid4VciRequestFailureKind.OutboundPolicyDenied"/>
    /// when the policy refused <paramref name="nonceEndpoint"/> before any dial,
    /// <see cref="Oid4VciRequestFailureKind.ErrorResponse"/> for a non-2xx status, or
    /// <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> when the success body is not
    /// well-formed JSON, repeats a member, or carries no <c>c_nonce</c>.
    /// </returns>
    private async ValueTask<Result<string, Oid4VciRequestFailure>> RequestNonceAsync(
        string accessToken,
        string tokenType,
        Uri nonceEndpoint,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        Oid4VciRequestFailure? policyDenial = EvaluateOutboundPolicy(nonceEndpoint, context, Configuration.OutboundFetchPolicy);
        if(policyDenial is not null)
        {
            return Result<string, Oid4VciRequestFailure>.Failure(policyDenial);
        }

        HttpResponseData response = await SendAuthorizedJsonPostAsync(
            nonceEndpoint, string.Empty, accessToken, tokenType, context, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode is < 200 or >= 300)
        {
            return Result<string, Oid4VciRequestFailure>.Failure(
                ParseErrorResponse(response.StatusCode, response.Body, nonceEndpoint));
        }

        ReadOnlySpan<byte> nonceJson = Encoding.UTF8.GetBytes(response.Body);
        if(!JwkJsonReader.IsWellFormedJsonDocument(nonceJson))
        {
            return Result<string, Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(
                    nonceEndpoint,
                    response.StatusCode,
                    "§7 the Nonce Response is not well-formed JSON, or contains a duplicate member name."));
        }

        string? nonce = JwkJsonReader.ExtractStringValue(nonceJson, CNonceUtf8);
        if(nonce is null)
        {
            return Result<string, Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(nonceEndpoint, response.StatusCode, "§7 the Nonce Response carried no c_nonce."));
        }

        return Result<string, Oid4VciRequestFailure>.Success(nonce);
    }


    /// <summary>
    /// Sends the <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">§8.2</see>
    /// Credential Request, a JSON body naming the target's <c>credential_identifier</c> or
    /// <c>credential_configuration_id</c> beside <c>proofs:{jwt:[proof]}</c> and an optional
    /// <c>credential_response_encryption</c>, and parses the full
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3">§8.3</see>
    /// response (every batch credential and the <c>notification_id</c>), or the
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9.2">§9.2</see>
    /// HTTP 202 deferral carrying <c>transaction_id</c> + <c>interval</c>.
    /// </summary>
    /// <returns>
    /// The full Credential Response outcome; or a failure:
    /// <see cref="Oid4VciRequestFailureKind.OutboundPolicyDenied"/> when the policy refused
    /// <paramref name="credentialEndpoint"/> before any dial, the §8.3.1
    /// <see cref="Oid4VciRequestFailureKind.ErrorResponse"/> for a non-2xx, non-202 status, or
    /// <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> when a 202 deferral carries no
    /// <c>transaction_id</c>, or a success body is not well-formed JSON, repeats a member, or
    /// carries no <c>credentials[].credential</c>.
    /// </returns>
    private async ValueTask<Result<CredentialIssuanceResult, Oid4VciRequestFailure>> RequestCredentialAsync(
        string accessToken,
        string tokenType,
        DateTimeOffset? accessTokenExpiresAt,
        CredentialRequestTarget target,
        string proofJwt,
        CredentialResponseEncryption? responseEncryption,
        Uri credentialEndpoint,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        string requestBody = await EncryptRequestIfAskedAsync(
            BuildCredentialRequestBody(target, proofJwt, responseEncryption),
            responseEncryption,
            cancellationToken).ConfigureAwait(false);

        Oid4VciRequestFailure? policyDenial = EvaluateOutboundPolicy(credentialEndpoint, context, Configuration.OutboundFetchPolicy);
        if(policyDenial is not null)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(policyDenial);
        }

        HttpResponseData response = await SendAuthorizedJsonPostAsync(
            credentialEndpoint, requestBody, accessToken, tokenType, context, cancellationToken).ConfigureAwait(false);

        //§8.3: a deferral answers HTTP 202 with transaction_id + interval (plaintext metadata, not the
        //encrypted credential payload); the Wallet later polls the Deferred Credential Endpoint.
        if(response.StatusCode == HttpAcceptedStatusCode)
        {
            return ParseDeferredPending(response.Body, response.StatusCode, accessToken, tokenType, accessTokenExpiresAt, credentialEndpoint);
        }

        if(response.StatusCode is < 200 or >= 300)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(
                ParseErrorResponse(response.StatusCode, response.Body, credentialEndpoint));
        }

        string? contentType = response.Headers.TryGetSingle(WellKnownHttpHeaderNames.ContentType);
        Result<string, Oid4VciRequestFailure> decryptOutcome = await DecryptResponseIfAskedAsync(
            response.Body, contentType, responseEncryption, credentialEndpoint, response.StatusCode, cancellationToken)
            .ConfigureAwait(false);

        if(!decryptOutcome.IsSuccess)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(decryptOutcome.Error);
        }

        return ParseIssuedCredentials(decryptOutcome.Value, response.StatusCode, accessToken, tokenType, accessTokenExpiresAt, credentialEndpoint);
    }


    /// <summary>
    /// Polls the OID4VCI 1.0 §9 Deferred Credential Endpoint for a previously-deferred issuance,
    /// presenting the <c>transaction_id</c> a prior <see cref="CredentialIssuanceResult"/> carried.
    /// Answers a value rather than throwing: the issued Credentials when ready (§9.2 HTTP 200), a
    /// still-deferred result echoing the <c>transaction_id</c> and <c>interval</c> when the Issuer
    /// answers §9.2 HTTP 202, or an
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9.3">§9.3</see>
    /// <see cref="Oid4VciRequestFailure"/> — for example <c>invalid_transaction_id</c> — for any
    /// other status.
    /// </summary>
    /// <param name="transactionId">The §9.1 <c>transaction_id</c> from the deferred issuance.</param>
    /// <param name="accessToken">The issuance access token (from <see cref="CredentialIssuanceResult.AccessToken"/>).</param>
    /// <param name="tokenType">The access token's type (<c>Bearer</c> or <c>DPoP</c>).</param>
    /// <param name="accessTokenExpiresAt">
    /// The instant <paramref name="accessToken"/> expires (from a prior
    /// <see cref="CredentialIssuanceResult.ExpiresAt"/>), carried over into a successful outcome's
    /// <see cref="CredentialIssuanceResult.ExpiresAt"/>, or <see langword="null"/> when unknown.
    /// </param>
    /// <param name="deferredCredentialEndpoint">The §9 Deferred Credential Endpoint URL.</param>
    /// <param name="responseEncryption">The §8.2 response-encryption ask carried over from issuance, or <see langword="null"/>.</param>
    /// <param name="context">The per-operation exchange context carrying the outbound-fetch policy evaluated before the dial.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The issued Credentials, a still-deferred result to poll again after the interval, or the
    /// §9.3 refusal.
    /// </returns>
    public async ValueTask<Result<CredentialIssuanceResult, Oid4VciRequestFailure>> PollDeferredCredentialAsync(
        string transactionId,
        string accessToken,
        string tokenType,
        DateTimeOffset? accessTokenExpiresAt,
        Uri deferredCredentialEndpoint,
        CredentialResponseEncryption? responseEncryption,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(transactionId);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenType);
        ArgumentNullException.ThrowIfNull(deferredCredentialEndpoint);
        ArgumentNullException.ThrowIfNull(context);

        string requestBody = await EncryptRequestIfAskedAsync(
            BuildDeferredRequestBody(transactionId), responseEncryption, cancellationToken).ConfigureAwait(false);

        Oid4VciRequestFailure? policyDenial = EvaluateOutboundPolicy(deferredCredentialEndpoint, context, Configuration.OutboundFetchPolicy);
        if(policyDenial is not null)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(policyDenial);
        }

        HttpResponseData response = await SendAuthorizedJsonPostAsync(
            deferredCredentialEndpoint, requestBody, accessToken, tokenType, context, cancellationToken).ConfigureAwait(false);

        //§9.2: still pending answers HTTP 202 echoing the transaction_id with a fresh interval.
        if(response.StatusCode == HttpAcceptedStatusCode)
        {
            return ParseDeferredPending(response.Body, response.StatusCode, accessToken, tokenType, accessTokenExpiresAt, deferredCredentialEndpoint);
        }

        //§9.3: any other non-2xx status is a Deferred Credential Error Response — a value the
        //caller inspects, never an exception, so invalid_transaction_id and a future poll after a
        //credential_request_denied are ordinary control flow.
        if(response.StatusCode is < 200 or >= 300)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(
                ParseErrorResponse(response.StatusCode, response.Body, deferredCredentialEndpoint));
        }

        string? contentType = response.Headers.TryGetSingle(WellKnownHttpHeaderNames.ContentType);
        Result<string, Oid4VciRequestFailure> decryptOutcome = await DecryptResponseIfAskedAsync(
            response.Body, contentType, responseEncryption, deferredCredentialEndpoint, response.StatusCode, cancellationToken)
            .ConfigureAwait(false);

        if(!decryptOutcome.IsSuccess)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(decryptOutcome.Error);
        }

        return ParseIssuedCredentials(decryptOutcome.Value, response.StatusCode, accessToken, tokenType, accessTokenExpiresAt, deferredCredentialEndpoint);
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
    /// <param name="context">The per-operation exchange context carrying the outbound-fetch policy evaluated before the dial.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see langword="null"/> when the Issuer acknowledged the notification — §11.2 requires an HTTP
    /// status in the 2xx range, with 204 (No Content) RECOMMENDED; otherwise the
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.3">§11.3</see>
    /// failure — the policy's <see cref="Oid4VciRequestFailureKind.OutboundPolicyDenied"/> refusal, or
    /// the endpoint's own <see cref="Oid4VciRequestFailureKind.ErrorResponse"/> such as <c>invalid_notification_id</c>.
    /// </returns>
    public async ValueTask<Oid4VciRequestFailure?> SendCredentialNotificationAsync(
        string notificationId,
        string notificationEvent,
        string accessToken,
        string tokenType,
        Uri notificationEndpoint,
        string? eventDescription,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(notificationId);
        ArgumentException.ThrowIfNullOrWhiteSpace(notificationEvent);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenType);
        ArgumentNullException.ThrowIfNull(notificationEndpoint);
        ArgumentNullException.ThrowIfNull(context);

        string requestBody = BuildNotificationRequestBody(notificationId, notificationEvent, eventDescription);

        Oid4VciRequestFailure? policyDenial = EvaluateOutboundPolicy(notificationEndpoint, context, Configuration.OutboundFetchPolicy);
        if(policyDenial is not null)
        {
            return policyDenial;
        }

        HttpResponseData response = await SendAuthorizedJsonPostAsync(
            notificationEndpoint, requestBody, accessToken, tokenType, context, cancellationToken).ConfigureAwait(false);

        //§11.2: success is HTTP 204 No Content; §11.3 maps failures to error bodies.
        if(response.StatusCode is < 200 or >= 300)
        {
            return ParseErrorResponse(response.StatusCode, response.Body, notificationEndpoint);
        }

        return null;
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
    /// <param name="body">The response body, plaintext JSON or a compact JWE.</param>
    /// <param name="contentType">The response's <c>Content-Type</c> header value, or <see langword="null"/>.</param>
    /// <param name="responseEncryption">The §8.2 response-encryption ask that produced this response, or <see langword="null"/>.</param>
    /// <param name="endpoint">The endpoint that answered, carried into a <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> failure.</param>
    /// <param name="statusCode">The success status the endpoint answered with, carried into a <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> failure.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The plaintext Credential Response JSON; or <see cref="Oid4VciRequestFailureKind.MalformedResponse"/>
    /// when <paramref name="responseEncryption"/> asked for encryption but <paramref name="contentType"/>
    /// is not <c>application/jwt</c> — the Issuer answered in clear, which is remote input, not the
    /// caller's own mistake.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="responseEncryption"/> asked for encryption but the wallet
    /// configuration has no <see cref="Oid4VciWalletConfiguration.DecryptResponse"/> delegate.
    /// </exception>
    private async ValueTask<Result<string, Oid4VciRequestFailure>> DecryptResponseIfAskedAsync(
        string body,
        string? contentType,
        CredentialResponseEncryption? responseEncryption,
        Uri endpoint,
        int statusCode,
        CancellationToken cancellationToken)
    {
        if(responseEncryption is null)
        {
            return Result<string, Oid4VciRequestFailure>.Success(body);
        }

        if(Configuration.DecryptResponse is null)
        {
            throw new InvalidOperationException(
                "The request asked for §10 response encryption but the wallet configuration has no "
                + "DecryptResponse delegate. Wire Oid4VciWalletConfiguration.DecryptResponse to read an "
                + "encrypted response.");
        }

        //§8.3 / §9.2: an encrypted response is application/jwt regardless of content; a clear answer
        //to an encryption ask is remote input — the Issuer's own mistake — so it answers
        //MalformedResponse rather than raising.
        if(contentType is not null
            && !contentType.Contains(WellKnownMediaTypes.Application.Jwt, StringComparison.OrdinalIgnoreCase))
        {
            return Result<string, Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(
                    endpoint,
                    statusCode,
                    $"§10 encryption was requested but the response Content-Type was '{contentType}', "
                    + $"not '{WellKnownMediaTypes.Application.Jwt}'. The Issuer did not encrypt the response."));
        }

        //An exception the application's own DecryptResponse delegate throws propagates as itself,
        //as a transport exception does — this seam is composition, not remote input.
        string decrypted = await Configuration.DecryptResponse(body, cancellationToken).ConfigureAwait(false);

        return Result<string, Oid4VciRequestFailure>.Success(decrypted);
    }


    /// <summary>
    /// Parses an issued-credentials response.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3">§8.3</see>:
    /// <c>credentials</c> is an array of objects each carrying a <c>credential</c> member; this reads
    /// EVERY object's credential string (a §8.2 batch carries more than one) plus the optional
    /// <c>notification_id</c>. The <see cref="JwkJsonReader"/> array-of-objects scanner keeps the wallet
    /// free of <c>System.Text.Json</c>. The body is remote input: a body that is not well-formed
    /// JSON or that carries no <c>credentials[].credential</c> answers
    /// <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> rather than raising.
    /// </summary>
    private static Result<CredentialIssuanceResult, Oid4VciRequestFailure> ParseIssuedCredentials(
        string responseJson,
        int statusCode,
        string accessToken,
        string tokenType,
        DateTimeOffset? accessTokenExpiresAt,
        Uri endpoint)
    {
        ReadOnlySpan<byte> json = Encoding.UTF8.GetBytes(responseJson);

        if(!JwkJsonReader.IsWellFormedJsonDocument(json))
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(endpoint, statusCode, "§8 the Credential Response is not well-formed JSON, or contains a duplicate member name."));
        }

        List<string>? credentials = JwkJsonReader.ExtractNestedStringValuesFromArray(
            json,
            Oid4VciCredentialParameterNames.CredentialsUtf8,
            Oid4VciCredentialParameterNames.CredentialUtf8);

        if(credentials is null || credentials.Count == 0)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(endpoint, statusCode, "§8 the Credential Response carried no credentials[].credential."));
        }

        string? notificationId = JwkJsonReader.ExtractStringValue(
            json, Oid4VciCredentialParameterNames.NotificationIdUtf8);

        return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Success(new CredentialIssuanceResult
        {
            Credentials = credentials,
            NotificationId = notificationId,
            AccessToken = accessToken,
            TokenType = tokenType,
            ExpiresAt = accessTokenExpiresAt
        });
    }


    /// <summary>
    /// Parses a deferral response.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3">§8.3</see>
    /// / <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9.2">§9.2</see>:
    /// a deferral carries <c>transaction_id</c> (REQUIRED) and <c>interval</c> (REQUIRED alongside it).
    /// The body is remote input: a deferral carrying no <c>transaction_id</c> answers
    /// <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> rather than raising.
    /// </summary>
    private static Result<CredentialIssuanceResult, Oid4VciRequestFailure> ParseDeferredPending(
        string body,
        int statusCode,
        string accessToken,
        string tokenType,
        DateTimeOffset? accessTokenExpiresAt,
        Uri endpoint)
    {
        ReadOnlySpan<byte> json = Encoding.UTF8.GetBytes(body);

        string? transactionId = JwkJsonReader.ExtractStringValue(json, Oid4VciCredentialParameterNames.TransactionIdUtf8);
        if(transactionId is null)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(endpoint, statusCode, "§9.2 the deferral carried no transaction_id."));
        }

        int? interval = JwkJsonReader.TryExtractLongValue(
            json, Oid4VciCredentialParameterNames.IntervalUtf8, out long intervalSeconds)
            ? (int)intervalSeconds
            : null;

        return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Success(new CredentialIssuanceResult
        {
            TransactionId = transactionId,
            DeferredIntervalSeconds = interval,
            AccessToken = accessToken,
            TokenType = tokenType,
            ExpiresAt = accessTokenExpiresAt
        });
    }


    /// <summary>
    /// Parses a structured OID4VCI error response into a value, walking the JSON body with the
    /// same span helpers the success paths use rather than a JSON library. A body that is not
    /// well-formed JSON, or carries no <c>error</c> member, still yields a refusal — the HTTP
    /// status alone is enough to know the request was refused; only the wire error detail is missing.
    /// </summary>
    private static Oid4VciRequestFailure ParseErrorResponse(int statusCode, string body, Uri endpoint)
    {
        ReadOnlySpan<byte> json = Encoding.UTF8.GetBytes(body);
        bool isWellFormed = JwkJsonReader.IsWellFormedJsonDocument(json);

        return new Oid4VciRequestFailure
        {
            Kind = Oid4VciRequestFailureKind.ErrorResponse,
            Endpoint = endpoint,
            StatusCode = statusCode,
            ErrorCode = isWellFormed
                ? JwkJsonReader.ExtractStringValue(json, OAuthRequestParameterNames.ErrorUtf8)
                : null,
            ErrorDescription = isWellFormed
                ? JwkJsonReader.ExtractStringValue(json, OAuthRequestParameterNames.ErrorDescriptionUtf8)
                : null
        };
    }


    /// <summary>
    /// Builds a <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> failure for a success
    /// status whose body, content type, or size breaks the request's section rule.
    /// </summary>
    /// <param name="endpoint">The endpoint that answered the malformed success.</param>
    /// <param name="statusCode">The success status code the endpoint answered with.</param>
    /// <param name="rule">The violated rule, in the library's own words.</param>
    private static Oid4VciRequestFailure MalformedResponseFailure(Uri endpoint, int statusCode, string rule) =>
        new()
        {
            Kind = Oid4VciRequestFailureKind.MalformedResponse,
            Endpoint = endpoint,
            StatusCode = statusCode,
            ErrorCode = null,
            ErrorDescription = rule
        };


    /// <summary>
    /// Builds an <see cref="Oid4VciRequestFailureKind.OutboundPolicyDenied"/> failure for a §4.1.3
    /// offer GET whose <see cref="OutboundFetchResult.Outcome"/> was not
    /// <see cref="OutboundFetchOutcome.Fetched"/> — the policy refused the target or a redirect hop,
    /// or refused to follow the redirect chain at all.
    /// </summary>
    /// <param name="endpoint">The §4.1.3 <c>credential_offer_uri</c> the policy refused.</param>
    /// <param name="outcome">The <see cref="OutboundFetchResult.Outcome"/> naming why the fetch did not complete.</param>
    /// <param name="denyReason">The policy's own denial reason, or <see langword="null"/> when none was given.</param>
    private static Oid4VciRequestFailure OutboundFetchOutcomeFailure(
        Uri endpoint, OutboundFetchOutcome outcome, string? denyReason) =>
        new()
        {
            Kind = Oid4VciRequestFailureKind.OutboundPolicyDenied,
            Endpoint = endpoint,
            StatusCode = null,
            ErrorCode = null,
            ErrorDescription = denyReason is not null ? $"{outcome}: {denyReason}" : outcome.ToString()
        };


    /// <summary>
    /// Builds the <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9.1">§9.1</see>
    /// Deferred Credential Request body — <c>{ transaction_id }</c>.
    /// </summary>
    private static string BuildDeferredRequestBody(string transactionId)
    {
        StringBuilder builder = new();
        _ = builder.Append('{');
        _ = builder.Append('"').Append(Oid4VciCredentialParameterNames.TransactionId).Append("\":\"");
        _ = builder.Append(transactionId).Append("\"}");

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
        _ = builder.Append('{');
        _ = builder.Append('"').Append(Oid4VciCredentialParameterNames.NotificationId).Append("\":\"");
        _ = builder.Append(notificationId).Append("\",\"");
        _ = builder.Append(Oid4VciCredentialParameterNames.Event).Append("\":\"");
        _ = builder.Append(notificationEvent).Append('"');

        if(!string.IsNullOrEmpty(eventDescription))
        {
            _ = builder.Append(",\"").Append(Oid4VciCredentialParameterNames.EventDescription).Append("\":\"");
            JsonAppender.AppendEscapedString(builder, eventDescription);
            _ = builder.Append('"');
        }

        _ = builder.Append('}');

        return builder.ToString();
    }


    /// <summary>
    /// Sends a §7/§8/§9/§11 authorized JSON POST, carrying the access-token authorization per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 §2.1</see>
    /// (<c>Authorization: Bearer &lt;token&gt;</c>) or, when <paramref name="tokenType"/> is
    /// DPoP-bound and <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/> is wired,
    /// through <see cref="DpopNonceRetry.SendWithNonceRetryAsync"/> — the helper shared with the §6
    /// Token Request and the AuthCode client — retrying exactly once on a <c>use_dpop_nonce</c>
    /// challenge (RFC 9449 §9) carrying a <c>DPoP-Nonce</c> response header.
    /// </summary>
    /// <remarks>
    /// Two challenge forms are recognised. Every OID4VCI 1.0 error response this Wallet's
    /// resource requests receive is a §8.3.1 Credential Error Response shape — HTTP 400 with the
    /// error code in the JSON body — so an OID4VCI Credential/Nonce/Deferred/Notification Endpoint
    /// signals <c>use_dpop_nonce</c> the same way the §6 Token Endpoint does (HTTP 400 +
    /// <c>error=use_dpop_nonce</c> in the body). RFC 9449 §9 additionally documents a generic
    /// resource server's own form: "an HTTP 401 (Unauthorized) error code with an accompanying
    /// <c>WWW-Authenticate: DPoP</c> value" carrying <c>error="use_dpop_nonce"</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see> auth-param
    /// form). This Wallet recognises either so it retries against a conformant Issuer regardless
    /// of which form its Credential Endpoint chose.
    /// </remarks>
    private async ValueTask<HttpResponseData> SendAuthorizedJsonPostAsync(
        Uri endpoint,
        string jsonBody,
        string accessToken,
        string tokenType,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(!WellKnownAuthenticationSchemes.IsDPoP(tokenType)
            || Configuration.ConstructDpopProofAsync is null
            || Configuration.DpopKey is null)
        {
            OutgoingHeaders bearerHeaders = OutgoingHeaders.Empty.WithAuthorization(
                WellKnownAuthenticationSchemes.Bearer, accessToken);

            return await Configuration.SendJsonPost(
                endpoint, jsonBody, bearerHeaders, context, cancellationToken).ConfigureAwait(false);
        }

        string authority = InMemoryDpopNonceCache.AuthorityFor(endpoint);
        string ath = await DpopProofValidator.ComputeAthAsync(
            accessToken, Configuration.Base64UrlEncoder, Configuration.MemoryPool, cancellationToken)
            .ConfigureAwait(false);

        return await DpopNonceRetry.SendWithNonceRetryAsync(
            (nonce, ct) => SendJsonPostWithDpopAsync(endpoint, jsonBody, accessToken, ath, nonce, context, ct),
            static candidate => IsUseDpopNonceChallenge(candidate),
            authority,
            Configuration.LookupDpopNonce,
            Configuration.StoreDpopNonce,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Recognises a resource-request <c>use_dpop_nonce</c> challenge in either wire form: an
    /// OID4VCI §8.3.1-shaped HTTP 400 with <c>error=use_dpop_nonce</c> in the JSON body, or the
    /// RFC 9449 §9 generic resource-server form — HTTP 401 with a <c>WWW-Authenticate: DPoP</c>
    /// value carrying <c>error="use_dpop_nonce"</c>.
    /// </summary>
    private static bool IsUseDpopNonceChallenge(HttpResponseData response) => response.StatusCode switch
    {
        400 => response.Body.Contains(OAuthErrors.UseDpopNonce, StringComparison.Ordinal),
        401 => response.Headers.TryGetSingle(WellKnownHttpHeaderNames.WwwAuthenticate)
            ?.Contains(OAuthErrors.UseDpopNonce, StringComparison.Ordinal) ?? false,
        _ => false
    };


    /// <summary>
    /// Mints one fresh DPoP proof bound to <paramref name="endpoint"/> and the presented
    /// <paramref name="accessToken"/> (via <paramref name="ath"/>) — embedding
    /// <paramref name="nonce"/> when supplied — and sends the JSON POST once.
    /// </summary>
    private async ValueTask<HttpResponseData> SendJsonPostWithDpopAsync(
        Uri endpoint,
        string jsonBody,
        string accessToken,
        string ath,
        string? nonce,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        string jti = await Configuration.GenerateIdentifierAsync!(
            WellKnownIdentifierPurposes.OAuthJti, context, cancellationToken).ConfigureAwait(false);

        DpopProofClaims claims = new()
        {
            Htm = HttpPostMethod,
            Htu = endpoint.GetLeftPart(UriPartial.Path),
            Iat = Configuration.TimeProvider.GetUtcNow(),
            Jti = jti,
            Nonce = nonce,
            Ath = ath
        };

        string proof = await Configuration.ConstructDpopProofAsync!(
            claims, Configuration.DpopKey!, cancellationToken).ConfigureAwait(false);

        OutgoingHeaders headers = OutgoingHeaders.Empty.WithDpopAndAccessToken(proof, accessToken);

        return await Configuration.SendJsonPost(
            endpoint, jsonBody, headers, context, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>
    /// Credential Request JSON body without <c>System.Text.Json</c>, the <c>Verifiable.OAuth</c>
    /// serialization firewall. The body names exactly the member <paramref name="target"/> holds,
    /// <c>credential_identifier</c> or <c>credential_configuration_id</c>, its value escaped through
    /// <see cref="JsonAppender.AppendStringField"/>; the proof is a compact JWS, a JSON-safe wire value;
    /// the optional <c>credential_response_encryption</c> object's <c>jwk</c> members and <c>enc</c>
    /// are written through <see cref="JsonAppender.AppendObject"/> and
    /// <see cref="JsonAppender.AppendStringField"/>, escaped.
    /// Section 8.2 on <c>credential_identifier</c>: "When this parameter is used, the
    /// credential_configuration_id MUST NOT be present."
    /// </summary>
    /// <param name="target">What the request names.</param>
    /// <param name="proofJwt">The section 7.2.1 holder key proof.</param>
    /// <param name="responseEncryption">The section 8.2 response-encryption ask, or <see langword="null"/>.</param>
    /// <returns>The request body.</returns>
    private static string BuildCredentialRequestBody(
        CredentialRequestTarget target,
        string proofJwt,
        CredentialResponseEncryption? responseEncryption)
    {
        (string targetMember, string targetValue) = target.CredentialIdentifier is { } credentialIdentifier
            ? (Oid4VciCredentialParameterNames.CredentialIdentifier, credentialIdentifier)
            : (Oid4VciCredentialParameterNames.CredentialConfigurationId, target.CredentialConfigurationId!);

        StringBuilder builder = new();
        _ = builder.Append('{');
        bool isFirstMember = true;
        JsonAppender.AppendStringField(builder, targetMember, targetValue, ref isFirstMember);
        _ = builder.Append(",\"").Append(Oid4VciCredentialParameterNames.Proofs).Append("\":{\"");
        _ = builder.Append(Oid4VciCredentialParameterNames.JwtProofType).Append("\":[\"");
        _ = builder.Append(proofJwt).Append("\"]}");

        if(responseEncryption is { Jwk: { } jwk, Enc: { } enc })
        {
            _ = builder.Append(",\"").Append(Oid4VciCredentialParameterNames.CredentialResponseEncryption);
            _ = builder.Append("\":{\"").Append(Oid4VciCredentialParameterNames.Jwk).Append("\":");
            JsonAppender.AppendObject(builder, jwk);
            bool isFirstEncryptionMember = false;
            JsonAppender.AppendStringField(builder, Oid4VciCredentialParameterNames.Enc, enc, ref isFirstEncryptionMember);
            _ = builder.Append('}');
        }

        _ = builder.Append('}');

        return builder.ToString();
    }


    /// <summary>
    /// Evaluates <paramref name="endpoint"/> against <paramref name="context"/>'s
    /// <see cref="OutboundFetchPolicy"/> before this client dials it, answering a failure value
    /// before any network contact when denied rather than dialing and failing later. Every
    /// endpoint this client dials — the §6 Token, §7 Nonce, §8 Credential, §9 Deferred Credential
    /// and §11 Notification Endpoints, plus the §4.1.3 by-reference Credential Offer URI — is read
    /// out of a Credential Offer or §12.2 Credential Issuer Metadata the Issuer itself serves, so a
    /// malicious or misconfigured document could point one at an internal, loopback, or
    /// cloud-metadata address: the same SSRF vector a discovered GET target is, gated the same way.
    /// </summary>
    /// <param name="endpoint">The endpoint this client is about to dial.</param>
    /// <param name="context">The per-operation exchange context carrying the policy.</param>
    /// <param name="configurationPolicy">
    /// <see cref="Oid4VciWalletConfiguration.OutboundFetchPolicy"/>, the deployment default applied
    /// when <paramref name="context"/> carries none.
    /// </param>
    /// <returns><see langword="null"/> when <paramref name="endpoint"/> is allowed; otherwise the denial.</returns>
    private static Oid4VciRequestFailure? EvaluateOutboundPolicy(
        Uri endpoint, ExchangeContext context, OutboundFetchPolicy configurationPolicy)
    {
        OutboundFetchPolicy policy = context.ResolveOutboundFetchPolicy(configurationPolicy);
        OutboundFetchDecision decision = policy.Evaluate(endpoint);

        if(decision.IsAllowed)
        {
            return null;
        }

        return new Oid4VciRequestFailure
        {
            Kind = Oid4VciRequestFailureKind.OutboundPolicyDenied,
            Endpoint = endpoint,
            StatusCode = null,
            ErrorCode = null,
            ErrorDescription = decision.DenyReason
        };
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
public sealed record Oid4VciIssuanceEndpoints
{
    /// <summary>The §6 Token Endpoint URL for the Pre-Authorized Code grant.</summary>
    public required Uri TokenEndpoint { get; init; }

    /// <summary>The §7 Nonce Endpoint URL.</summary>
    public required Uri NonceEndpoint { get; init; }

    /// <summary>The §8 Credential Endpoint URL.</summary>
    public required Uri CredentialEndpoint { get; init; }
}
