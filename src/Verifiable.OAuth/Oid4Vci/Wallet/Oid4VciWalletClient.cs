using System.Buffers;
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
/// <c>authorization_details</c> with the span reader
/// (<see cref="GrantedCredentialAuthorizationReader"/>) and choose the target through
/// <see cref="CredentialRequestTarget.FromGrantedAuthorizations"/>: by the first
/// <c>credential_identifiers</c> value granted for the requested configuration, by the configuration
/// when the response returned no <c>openid_credential</c> object, and no request when the response
/// granted identifiers for other configurations only. A wallet on the authorization-code path reads
/// the same grant from its token result
/// (<see cref="AuthCode.AuthCodeFlowEndpointResult.GrantedCredentialAuthorizations"/>) and chooses
/// through the same factory.
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
    /// document fetch: a guarded response read with one size decision, an exact
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
    /// when the content type is not <c>application/json</c> or the body does not
    /// satisfy §4.1.1's <c>credential_issuer</c> and <c>credential_configuration_ids</c> rules —
    /// the same rules <see cref="CredentialOfferSerializer.FromJson"/> raises for a caller-supplied
    /// offer, answered here as a value since the body is the Issuer's own.
    /// <see cref="Oid4VciRequestFailureKind.TooLarge"/> retains a declared or observed excess, and
    /// <see cref="Oid4VciRequestFailureKind.Unreachable"/> retains an unrelated transport failure kind.
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
        cancellationToken.ThrowIfCancellationRequested();

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

        OutboundFetchResult fetch = await OutboundFetch.FetchAsync(
            request, context, Configuration.FetchCredentialOffer, cancellationToken).ConfigureAwait(false);

        if(fetch.FailureKind is Type failureKind)
        {
            return Result<CredentialOffer, Oid4VciRequestFailure>.Failure(new Oid4VciRequestFailure
            {
                Kind = Oid4VciRequestFailureKind.Unreachable,
                Endpoint = credentialOfferUri,
                StatusCode = null,
                FailureKind = failureKind
            });
        }

        if(fetch.TooLarge is OutboundResponseTooLarge tooLarge)
        {
            return Result<CredentialOffer, Oid4VciRequestFailure>.Failure(new Oid4VciRequestFailure
            {
                Kind = Oid4VciRequestFailureKind.TooLarge,
                Endpoint = credentialOfferUri,
                StatusCode = null,
                TooLarge = tooLarge
            });
        }

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
    /// member. After an authorization-code exchange the caller chooses it through
    /// <see cref="CredentialRequestTarget.FromGrantedAuthorizations"/> over the token result's
    /// <see cref="AuthCode.AuthCodeFlowEndpointResult.GrantedCredentialAuthorizations"/>, which the
    /// library's Token Response parser fills. The Pre-Authorized Code entry points read their own
    /// Token Response through the same reader and choose the target through the same factory.
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
    /// (<see cref="GrantedCredentialAuthorizationReader.TryRead"/>), and the answer keeps what they
    /// grant with the token as the target of the Credential Request, chosen through
    /// <see cref="CredentialRequestTarget.FromGrantedAuthorizations"/>: the first
    /// <c>credential_identifiers</c> value of the first <c>openid_credential</c> object naming
    /// <paramref name="credentialConfigurationId"/>, or the configuration itself when the response
    /// returned no <c>openid_credential</c> object.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// </remarks>
    /// <returns>
    /// The access token, its type, its computed expiry and the Credential Request's target; or a failure:
    /// <see cref="Oid4VciRequestFailureKind.OutboundPolicyDenied"/> when the policy refused
    /// <paramref name="tokenEndpoint"/> before any dial, <see cref="Oid4VciRequestFailureKind.ErrorResponse"/>
    /// for the RFC 6749 Section 5.2 Token Error Response a non-2xx status carries,
    /// <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> for a Token Error Response whose
    /// <c>error</c> is empty or holds a char outside <c>%x20-21 / %x23-5B / %x5D-7E</c>, or
    /// <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> when the success body is not
    /// well-formed JSON, repeats a member, carries no <c>access_token</c>, carries an empty
    /// <c>access_token</c>, one holding a char outside <c>%x20-7E</c> (RFC 6749 Appendix A.12) or one
    /// that is not a <c>token68</c> credential (RFC 9110 Section 11.2; the Token Response parser holds
    /// Appendix A.12 alone, since it serves clients that carry the token elsewhere), or a
    /// <c>token_type</c> that is neither a type-name nor an RFC 3986 URI-reference (Appendix A.13),
    /// carries <c>authorization_details</c> that are not a non-empty array of objects, an entry without a
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

        //The request carries the pre-authorized code; a redirect followed would re-send it to the origin
        //its Location field names (RFC 9110 Section 15.4.8), so the Wallet refuses it.
        if(RefuseRedirection(tokenEndpoint, response) is Oid4VciRequestFailure tokenRedirectRefusal)
        {
            return Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(tokenRedirectRefusal);
        }

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

        //RFC 6749 Appendix A.12: the token is one or more chars in %x20-7E and is composed into the
        //Authorization header of every later request, so an empty value, or a decoded value holding a
        //char outside the range, is refused, never echoed.
        if(accessToken.Length == 0)
        {
            return Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(
                    tokenEndpoint,
                    response.StatusCode,
                    "RFC 6749 Appendix A.12 the Token Response's access_token is empty."));
        }

        if(!OAuthResponseParsers.IsVisibleCharacterText(accessToken))
        {
            return Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(
                    tokenEndpoint,
                    response.StatusCode,
                    "RFC 6749 Appendix A.12 the Token Response's access_token holds a char outside %x20-7E."));
        }

        //RFC 9110 Section 11.2: the wallet presents the token as the credential of an Authorization header
        //under the Bearer or the DPoP scheme, whose syntax is token68, so a token the header cannot carry
        //is refused here, before any later request.
        if(!IsToken68(accessToken))
        {
            return Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(
                    tokenEndpoint,
                    response.StatusCode,
                    "RFC 9110 Section 11.2 the Token Response's access_token is not a token68 credential an Authorization header can carry."));
        }

        //RFC 6749 Section 5.1 makes token_type REQUIRED: "token_type REQUIRED. The type of the token
        //issued as described in Section 7.1. Value is case insensitive." An absent one is read as Bearer;
        //a present one is held to Appendix A.13, a type-name or an RFC 3986 URI-reference as
        //OAuthResponseParsers.IsTokenType reads it with its span recognizer of the URI-reference grammar.
        string tokenType = JwkJsonReader.ExtractStringValue(tokenJson, OAuthRequestParameterNames.TokenTypeUtf8)
            ?? WellKnownAuthenticationSchemes.Bearer;
        if(!OAuthResponseParsers.IsTokenType(tokenType))
        {
            return Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(
                    tokenEndpoint,
                    response.StatusCode,
                    "RFC 6749 Appendix A.13 the Token Response's token_type is neither a type-name nor an RFC 3986 URI-reference."));
        }

        DateTimeOffset? expiresAt = JwkJsonReader.TryExtractLongValue(
            tokenJson, OAuthRequestParameterNames.ExpiresInUtf8, out long expiresInSeconds)
            ? requestedAt.AddSeconds(expiresInSeconds)
            : null;

        //Section 6.2: the openid_credential objects the response returned name the identifiers the
        //Credential Request must use; without them the request names the configuration.
        if(!GrantedCredentialAuthorizationReader.TryRead(
            tokenJson, out IReadOnlyList<GrantedCredentialAuthorization> grantedAuthorizations))
        {
            return Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(
                MalformedResponseFailure(
                    tokenEndpoint,
                    response.StatusCode,
                    "Section 6.2 the Token Response's authorization_details are not a non-empty array of objects, "
                    + "an entry lacks a string type, or an "
                    + "openid_credential object lacks its credential_configuration_id or a non-empty "
                    + "credential_identifiers, or lists an identifier that is empty or white space."));
        }

        CredentialRequestTarget? target = CredentialRequestTarget.FromGrantedAuthorizations(
            credentialConfigurationId, grantedAuthorizations);

        return target switch
        {
            null =>
                Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Failure(
                    MalformedResponseFailure(
                        tokenEndpoint,
                        response.StatusCode,
                        "Section 6.2 the Token Response returned credential_identifiers for no openid_credential object "
                        + "naming the requested credential_configuration_id.")),
            _ =>
                Result<(string, string, DateTimeOffset?, CredentialRequestTarget), Oid4VciRequestFailure>.Success(
                    (accessToken, tokenType, expiresAt, target))
        };
    }


    /// <summary>
    /// Sends the §6 Token Request once when <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>
    /// carries no DPoP key, or through <see cref="DpopNonceRetry.SendWithNonceRetryAsync"/> — the
    /// helper shared with the AuthCode token endpoint's own retry — when it does, embedding a fresh
    /// proof on every attempt and retrying exactly once on an RFC 9449 Section 8 <c>use_dpop_nonce</c>
    /// challenge (HTTP 400 + <c>use_dpop_nonce</c> as the JSON object's own <c>error</c> member + a
    /// <c>DPoP-Nonce</c> response header), read by <see cref="DpopNonceRetry.IsErrorBodyNonceChallenge"/>.
    /// The token endpoint keeps its own nonce, under its scheme, authority and path, apart from the nonce of
    /// every resource endpoint (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>:
    /// "a nonce issued by any of them should be used only at the issuing server").
    /// </summary>
    /// <param name="formFields">The Token Request's form fields.</param>
    /// <param name="tokenEndpoint">The Token Endpoint the request is sent to.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport delegate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The Token Endpoint's answer, the retry's answer when a nonce challenge triggered one.</returns>
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

        return await DpopNonceRetry.SendWithNonceRetryAsync(
            (nonce, ct) => SendFormPostWithDpopAsync(formFields, tokenEndpoint, nonce, context, ct),
            candidate => DpopNonceRetry.IsErrorBodyNonceChallenge(candidate, Configuration.MemoryPool),
            tokenEndpoint,
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

        //The request carries the access token; a redirect followed would re-send it to the origin its
        //Location field names (RFC 9110 Section 15.4.8), so the Wallet refuses it.
        if(RefuseRedirection(nonceEndpoint, response) is Oid4VciRequestFailure nonceRedirectRefusal)
        {
            return Result<string, Oid4VciRequestFailure>.Failure(nonceRedirectRefusal);
        }

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

        //The request carries the access token and the key proof; a redirect followed would re-send both to
        //the origin its Location field names (RFC 9110 Section 15.4.8), so the Wallet refuses it.
        if(RefuseRedirection(credentialEndpoint, response) is Oid4VciRequestFailure credentialRedirectRefusal)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(credentialRedirectRefusal);
        }

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

        //The request carries the access token; a redirect followed would re-send it to the origin its
        //Location field names (RFC 9110 Section 15.4.8), so the Wallet refuses it.
        if(RefuseRedirection(deferredCredentialEndpoint, response) is Oid4VciRequestFailure deferredRedirectRefusal)
        {
            return Result<CredentialIssuanceResult, Oid4VciRequestFailure>.Failure(deferredRedirectRefusal);
        }

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
    /// failure — the policy's <see cref="Oid4VciRequestFailureKind.OutboundPolicyDenied"/> refusal, the
    /// <see cref="Oid4VciRequestFailureKind.RedirectRefused"/> refusal of a redirect answer, or the
    /// endpoint's own <see cref="Oid4VciRequestFailureKind.ErrorResponse"/> such as <c>invalid_notification_id</c>.
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

        //The request carries the access token; a redirect followed would re-send it to the origin its
        //Location field names (RFC 9110 Section 15.4.8), so the Wallet refuses it.
        if(RefuseRedirection(notificationEndpoint, response) is Oid4VciRequestFailure notificationRedirectRefusal)
        {
            return notificationRedirectRefusal;
        }

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
    /// The error members are held to the sets the Token Response parser holds them to
    /// (<see cref="OAuthResponseParsers.IsErrorCharacterText"/>): an <c>error</c> that is empty or holds a
    /// char outside <c>%x20-21 / %x23-5B / %x5D-7E</c> is no code the wallet can act on and answers a
    /// <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> with a fixed rule text that echoes none
    /// of it; an <c>error_description</c> holding such a char is read as absent. The wallet reads no
    /// <c>error_uri</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This one reader serves every endpoint the wallet calls (the token, nonce, credential, deferred
    /// credential and notification endpoints) and holds each one's error members to the one set below.
    /// For the token endpoint that set is RFC 6749 Section 5.2's MUST. For the credential endpoint, and
    /// for the deferred credential endpoint, whose error response OpenID4VCI 1.0 Section 9.3 constructs as
    /// Section 8.3.1 defines it, the <c>error_description</c> set is Section 8.3.1.2's MUST, while that
    /// section asks of the <c>error</c> code only that it SHOULD be a single ASCII code. The nonce
    /// endpoint (Section 7 defines no error response) and the notification endpoint (Section 11.3 defines
    /// the <c>error</c> member only for its 400 JSON body, which SHOULD be one of its codes) are held to
    /// the same set by this
    /// library's reading, as is the <c>error</c> code of every endpoint but the token endpoint.
    /// </para>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B /
    /// %x5D-7E." And: "Values for the "error_description" parameter MUST NOT include characters outside
    /// the set %x20-21 / %x23-5B / %x5D-7E."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.7">RFC 6749 Appendix A.7</see>:
    /// "error             = 1*NQSCHAR".
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OpenID4VCI 1.0 Section 8.3.1.2</see>:
    /// "error: REQUIRED. The error parameter SHOULD be a single ASCII [USASCII] error code from the
    /// following:" And: "The values for the error_description parameter MUST NOT include characters
    /// outside the set %x20-21 / %x23-5B / %x5D-7E."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9.3">OpenID4VCI 1.0 Section 9.3</see>:
    /// "When the Deferred Credential Request is invalid, the Credential Issuer constructs the error
    /// response as defined in Section 8.3.1."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.3">OpenID4VCI 1.0 Section 11.3</see>:
    /// "error: REQUIRED. The value of the error parameter SHOULD be one of the following ASCII [USASCII]
    /// error codes:"
    /// </para>
    /// </remarks>
    /// <param name="statusCode">The non-2xx status the endpoint answered with.</param>
    /// <param name="body">The error response body.</param>
    /// <param name="endpoint">The endpoint that refused the request.</param>
    /// <returns>The refusal, or the malformed-response failure for an error code outside its grammar.</returns>
    private static Oid4VciRequestFailure ParseErrorResponse(int statusCode, string body, Uri endpoint)
    {
        ReadOnlySpan<byte> json = Encoding.UTF8.GetBytes(body);
        bool isWellFormed = JwkJsonReader.IsWellFormedJsonDocument(json);
        string? errorCode = isWellFormed
            ? JwkJsonReader.ExtractStringValue(json, OAuthRequestParameterNames.ErrorUtf8)
            : null;

        if(errorCode is not null && (errorCode.Length == 0 || !OAuthResponseParsers.IsErrorCharacterText(errorCode)))
        {
            return MalformedResponseFailure(
                endpoint,
                statusCode,
                "RFC 6749 Section 5.2 the error response's error is empty or holds a char outside %x20-21 / %x23-5B / %x5D-7E.");
        }

        string? errorDescription = isWellFormed
            ? JwkJsonReader.ExtractStringValue(json, OAuthRequestParameterNames.ErrorDescriptionUtf8)
            : null;

        return new Oid4VciRequestFailure
        {
            Kind = Oid4VciRequestFailureKind.ErrorResponse,
            Endpoint = endpoint,
            StatusCode = statusCode,
            ErrorCode = errorCode,
            ErrorDescription = errorDescription is not null && OAuthResponseParsers.IsErrorCharacterText(errorDescription)
                ? errorDescription
                : null
        };
    }


    /// <summary>
    /// Whether an <c>access_token</c> is an RFC 9110 Section 11.2 <c>token68</c> credential, the syntax of
    /// the <c>Authorization</c> header's credential under the <c>Bearer</c> and <c>DPoP</c> schemes the
    /// wallet presents it with: one or more of an ASCII letter, an ASCII digit, <c>-</c>, <c>.</c>,
    /// <c>_</c>, <c>~</c>, <c>+</c> or <c>/</c> (<see cref="Token68Characters"/>), followed by any number of
    /// <c>=</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>:
    /// "token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="".
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>:
    /// "b64token    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="".
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>:
    /// "The syntax of the Authorization header field for the DPoP scheme uses the token68 syntax defined
    /// in Section 11.2 of [RFC9110] for credentials and is repeated below for ease of reference."
    /// </remarks>
    /// <param name="value">The decoded <c>access_token</c> value.</param>
    /// <returns><see langword="true"/> when the value is a <c>token68</c> credential.</returns>
    private static bool IsToken68(ReadOnlySpan<char> value)
    {
        ReadOnlySpan<char> beforePadding = value.TrimEnd('=');

        return !beforePadding.IsEmpty && beforePadding.IndexOfAnyExcept(Token68Characters) < 0;
    }


    /// <summary>
    /// The chars of a <c>token68</c> credential before its padding: the ASCII letters and digits, <c>-</c>,
    /// <c>.</c>, <c>_</c>, <c>~</c>, <c>+</c> and <c>/</c>.
    /// </summary>
    private static SearchValues<char> Token68Characters { get; } =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/");


    /// <summary>
    /// Builds a <see cref="Oid4VciRequestFailureKind.MalformedResponse"/> failure for a response whose
    /// body, content type or <c>error</c> member breaks the request's section rule: a success
    /// status, or an error response whose <c>error</c> is empty or outside its set.
    /// </summary>
    /// <param name="endpoint">The endpoint that answered the malformed response.</param>
    /// <param name="statusCode">The status code the endpoint answered with.</param>
    /// <param name="rule">The violated rule, in the library's own words.</param>
    /// <returns>The malformed-response failure, carrying <paramref name="rule"/> as its description and no error code.</returns>
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
    /// Builds the <see cref="Oid4VciRequestFailureKind.RedirectRefused"/> failure when
    /// <paramref name="response"/> is a redirect, an HTTP status of the 3xx class, answering a request
    /// that carried a credential: the refusal is recorded and typed by
    /// <see cref="CredentialBearingRedirect.Refuse"/> and the Wallet sends nothing further.
    /// </summary>
    /// <param name="endpoint">The endpoint the request was sent to.</param>
    /// <param name="response">The endpoint's answer, as the single-hop transport returned it.</param>
    /// <returns>The failure, or <see langword="null"/> when the status is not of the 3xx class.</returns>
    private static Oid4VciRequestFailure? RefuseRedirection(Uri endpoint, HttpResponseData response) =>
        CredentialBearingRedirect.Refuse(endpoint, response) is OAuthRedirectRefused refusal
            ? new Oid4VciRequestFailure
            {
                Kind = Oid4VciRequestFailureKind.RedirectRefused,
                Endpoint = endpoint,
                StatusCode = response.StatusCode,
                ErrorCode = null,
                ErrorDescription = refusal.Support.Summary,
                RedirectRefusal = refusal
            }
            : null;


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
    /// of which form its Credential Endpoint chose. Each endpoint keeps its own nonce, under its scheme,
    /// authority and path, so the Nonce, Credential, Deferred and Notification Endpoints and the Token Endpoint
    /// never carry one another's nonce
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "a nonce issued by
    /// any of them should be used only at the issuing server").
    /// </remarks>
    /// <param name="endpoint">The resource endpoint the request is sent to.</param>
    /// <param name="jsonBody">The request's JSON body.</param>
    /// <param name="accessToken">The access token presented.</param>
    /// <param name="tokenType">The access token's type, <c>DPoP</c> or <c>Bearer</c>.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport delegate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The endpoint's answer, the retry's answer when a nonce challenge triggered one.</returns>
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

        string ath = await DpopProofValidator.ComputeAthAsync(
            accessToken, Configuration.Base64UrlEncoder, Configuration.MemoryPool, cancellationToken)
            .ConfigureAwait(false);

        return await DpopNonceRetry.SendWithNonceRetryAsync(
            (nonce, ct) => SendJsonPostWithDpopAsync(endpoint, jsonBody, accessToken, ath, nonce, context, ct),
            candidate => IsUseDpopNonceChallenge(candidate, Configuration.MemoryPool),
            endpoint,
            Configuration.LookupDpopNonce,
            Configuration.StoreDpopNonce,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Recognises a resource-request <c>use_dpop_nonce</c> challenge in either wire form: an HTTP 400 shaped as the
    /// OpenID4VCI 1.0 Section 8.3.1.2 Credential Error Response whose JSON object carries <c>use_dpop_nonce</c>, the
    /// RFC 9449 Section 8 error code, as its own <c>error</c> member
    /// (<see cref="DpopNonceRetry.IsErrorBodyNonceChallenge"/>; reading a resource's 400 form as a nonce challenge is
    /// the library's own rule), or the RFC 9449 Section 9 resource-server form, HTTP 401 with a
    /// <c>WWW-Authenticate: DPoP</c> challenge whose <c>error</c> auth-param is <c>use_dpop_nonce</c>
    /// (<see cref="DpopNonceRetry.IsWwwAuthenticateNonceChallenge"/>). The text <c>use_dpop_nonce</c>
    /// anywhere else in the answer, such as the value of an auth-param the wallet does not know,
    /// is no challenge: RFC 9449 Section 7.1, "unknown parameters MUST be ignored by recipients."
    /// </summary>
    /// <param name="response">The answer to read.</param>
    /// <param name="memoryPool">The pool the 400 body's UTF-8 copy is rented from.</param>
    /// <returns><see langword="true"/> when the answer is a nonce challenge.</returns>
    private static bool IsUseDpopNonceChallenge(HttpResponseData response, BaseMemoryPool memoryPool) => response.StatusCode switch
    {
        400 => DpopNonceRetry.IsErrorBodyNonceChallenge(response, memoryPool),
        401 => DpopNonceRetry.IsWwwAuthenticateNonceChallenge(response),
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
