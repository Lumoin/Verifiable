using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;

using Verifiable.OAuth.Server.Metadata;
namespace Verifiable.OAuth.Server;

/// <summary>
/// Loads a <see cref="ClientRecord"/> from the backing store by tenant identifier.
/// </summary>
/// <remarks>
/// <para>
/// Called at the start of every request after the dispatcher has resolved the tenant
/// via <see cref="AuthorizationServerIntegration.ExtractTenantIdAsync"/>. The implementation
/// looks up the registration in whatever per-tenant store it maintains.
/// </para>
/// <para>
/// Return <see langword="null"/> when the registration is not found — the handler returns
/// <c>invalid_client</c> without leaking whether the identifier exists. The
/// <paramref name="context"/> carries request-scoped data the implementation can read
/// for finer-grained decisions (e.g., region routing, feature flags).
/// </para>
/// </remarks>
public delegate ValueTask<ClientRecord?> LoadClientRegistrationDelegate(
    TenantId tenantId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves a private signing key by <see cref="KeyId"/>. Parallel to
/// <see cref="ResolveServerHmacKeyDelegate"/> for symmetric HMAC keys —
/// pure byte-loading with no rotation or selection logic. The kid is chosen
/// at the call site by <see cref="SelectSigningKeyDelegate"/> (or its default)
/// and passed here as a typed identifier.
/// </summary>
/// <remarks>
/// <para>
/// Return <see langword="null"/> when the key is unavailable — the handler returns
/// <c>server_error</c> without leaking key store details.
/// </para>
/// <para>
/// The <paramref name="tenantId"/> parameter enables per-tenant key isolation;
/// applications that don't need it ignore the value. Production deployments
/// backing this delegate with an HSM or KMS typically scope key handles by tenant.
/// </para>
/// </remarks>
public delegate ValueTask<PrivateKeyMemory?> ServerSigningKeyResolverDelegate(
    KeyId keyId,
    TenantId tenantId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves a public verification key by <see cref="KeyId"/>. Mirrors
/// <see cref="ServerSigningKeyResolverDelegate"/> for the verification side.
/// </summary>
/// <remarks>
/// The <paramref name="tenantId"/> parameter enables per-tenant key isolation;
/// applications that don't need it ignore the value.
/// </remarks>
public delegate ValueTask<PublicKeyMemory?> ServerVerificationKeyResolverDelegate(
    KeyId keyId,
    TenantId tenantId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Serializes a <see cref="PublicKeyMemory"/> to a JWKS JSON string for the JWKS endpoint.
/// </summary>
public delegate ValueTask<string> SerializeJwksDelegate(
    PublicKeyMemory publicKey,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Builds the <see cref="JwksDocument"/> to serve at the JWKS endpoint for the given
/// client registration.
/// </summary>
/// <remarks>
/// <para>
/// The delegate receives the full <see cref="ClientRecord"/> and the per-request
/// context bag so the implementation can make context-sensitive decisions — for example,
/// returning only a subset of keys based on the caller's tenant, filtering by algorithm
/// support, or hiding keys that are in a rotation grace period. The library never
/// prescribes which keys to include.
/// </para>
/// <para>
/// Key rotation requires returning both the old and the new signing key during the
/// transition window so clients that cached the old key can still verify tokens signed
/// with it. The application's key store knows which keys are active for a given
/// registration — the delegate reads from that store and assembles the document.
/// </para>
/// <para>
/// For HSM or TPM-backed keys the delegate calls the hardware's public-key export
/// function; the private key never leaves the device.
/// </para>
/// </remarks>
/// <param name="registration">
/// The <see cref="ClientRecord"/> whose JWKS is being served.
/// </param>
/// <param name="context">
/// The per-request context bag carrying whatever the ASP.NET skin chose to surface.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The <see cref="JwksDocument"/> to serialize and return in the HTTP response body.
/// </returns>
public delegate ValueTask<JwksDocument> BuildJwksDocumentDelegate(
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Fetches and validates a Client ID Metadata Document for CIMD clients.
/// </summary>
/// <remarks>
/// Return <see langword="null"/> when the document cannot be fetched or fails
/// validation. Caching with appropriate TTL is the responsibility of the implementation.
/// </remarks>
public delegate ValueTask<ClientRecord?> ResolveClientMetadataDelegate(
    Uri clientMetadataUri,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves a <see cref="PrivateKeyMemory"/> by key identifier for decrypting
/// Authorization Response JWEs in OID4VP flows.
/// </summary>
/// <remarks>
/// Return <see langword="null"/> when the key is unavailable — the handler returns
/// <c>server_error</c> without leaking key store details.
/// </remarks>
public delegate ValueTask<PrivateKeyMemory?> ServerDecryptionKeyResolverDelegate(
    KeyId keyId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Contributes additional fields to the Authorization Server's discovery document
/// (<c>/.well-known/openid-configuration</c> and equivalents).
/// </summary>
/// <remarks>
/// <para>
/// The library's <c>MetadataEndpoints.BuildDiscovery</c> handler emits the base
/// OAuth 2.0 and OIDC fields it can compute from the registration's capability set
/// — <c>issuer</c>, <c>jwks_uri</c>, <c>token_endpoint</c>, and the like. Applications
/// supply this delegate to advertise additional OIDC, FAPI, OID4VP, OID4VCI, OpenID
/// Federation, or deployment-specific fields the library does not own — for example
/// <c>id_token_signing_alg_values_supported</c>, <c>subject_types_supported</c>,
/// <c>userinfo_endpoint</c>, <c>end_session_endpoint</c>,
/// <c>backchannel_authentication_endpoint</c>.
/// </para>
/// <para>
/// The library writes its base fields first; contributed fields are merged
/// afterwards in the order returned. The contribution is strictly additive —
/// the library's base fields take precedence over any contributed field with a
/// duplicate name.
/// </para>
/// <para>
/// Return <see cref="DiscoveryDocumentContribution.Empty"/> when there is
/// nothing to contribute for a given request. Each contributed field is a
/// concrete subtype of <see cref="DiscoveryField"/> typed to the JSON value
/// shape the library knows how to serialize.
/// </para>
/// </remarks>
/// <param name="registration">The <see cref="ClientRecord"/> the discovery document describes.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The contributed discovery fields.</returns>
public delegate ValueTask<DiscoveryDocumentContribution> ContributeDiscoveryFieldsDelegate(
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Contributes the per-entity-type metadata blocks, authority hints, and
/// extension claims for the entity's own OpenID Federation 1.0 Entity
/// Configuration JWT served at <c>/.well-known/openid-federation</c>.
/// </summary>
/// <remarks>
/// <para>
/// The library produces the EC's structural claims (<c>iss</c>, <c>sub</c>,
/// <c>iat</c>, <c>exp</c>, <c>jwks</c>) from
/// <see cref="ClientRecord.FederationEntityId"/> and the registration's
/// federation signing keys; the application's response to this delegate
/// supplies everything else — typically per-entity-type metadata blocks
/// such as <c>openid_relying_party</c>, <c>openid_provider</c>, or
/// <c>federation_entity</c>.
/// </para>
/// <para>
/// Return <see cref="Federation.FederationEntityConfigurationContribution.Empty"/>
/// when there is nothing to contribute. The library-emitted structural
/// claims are sufficient on their own for a leaf entity that participates
/// in chain validation without declaring any per-entity-type role.
/// </para>
/// </remarks>
/// <param name="registration">The <see cref="ClientRecord"/> whose EC is being served.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The contributed metadata, authority hints, and additional claims.</returns>
public delegate ValueTask<Federation.FederationEntityConfigurationContribution> ContributeFederationMetadataDelegate(
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves the Subordinate Statement body the issuing entity asserts
/// about the queried subject. Invoked by the
/// <c>federation_fetch_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.1">Federation §8.1</see>
/// when an inbound GET arrives with a <c>sub</c> query parameter.
/// </summary>
/// <remarks>
/// <para>
/// The library produces the structural envelope (<c>iss</c>, <c>sub</c>,
/// <c>iat</c>, <c>exp</c>) and signs the resulting JWT with the entity's
/// federation signing key; the application's response to this delegate
/// supplies the subject's <c>jwks</c> (required) plus any per-subject
/// <c>metadata_policy</c>, <c>metadata</c>, <c>constraints</c>, or
/// extension claims.
/// </para>
/// <para>
/// Returning <see langword="null"/> tells the library the queried subject
/// is not a known subordinate; the endpoint then responds with HTTP 404.
/// </para>
/// </remarks>
/// <param name="subject">The Entity Identifier queried via the <c>sub</c> parameter.</param>
/// <param name="registration">The issuing entity's <see cref="ClientRecord"/>.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The contributed Subordinate Statement body, or <see langword="null"/>
/// when the subject is not a known subordinate.
/// </returns>
public delegate ValueTask<Federation.SubordinateStatementContribution?> ResolveSubordinateStatementDelegate(
    Federation.EntityIdentifier subject,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves the immediate subordinates the issuing entity lists at its
/// <c>federation_list_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.2">Federation §8.2</see>
/// when an inbound GET arrives. The library matches the request, parses any
/// filter parameters, serialises the returned identifiers as the unsigned
/// JSON array §8.2 mandates, and short-circuits the response; the
/// application's response to this delegate is the membership list itself.
/// </summary>
/// <remarks>
/// <para>
/// The §8.2 response is an unsigned JSON array of Entity Identifier strings
/// — distinct from the signed Subordinate Statement a
/// <c>federation_fetch_endpoint</c> returns. The list states only
/// <em>who</em> the subordinates are; the per-subject assertions come from
/// <see cref="ResolveSubordinateStatementDelegate"/>.
/// </para>
/// <para>
/// The library passes the parsed <paramref name="entityTypeFilter"/> — the
/// §8.2 <c>entity_type</c> query parameter — when present. An entity that
/// does not implement the filter MAY ignore it and return its full
/// membership; an entity that does implement it returns only subordinates
/// declaring that Entity Type. Returning an empty list is valid (a
/// federation entity with no subordinates, or a filter that matches none).
/// </para>
/// </remarks>
/// <param name="entityTypeFilters">
/// The <c>entity_type</c> filters from the request — §8.2.1 permits the
/// parameter to repeat, and the result must include subordinates declaring
/// <em>any</em> of the listed Entity Types. Empty when the requester asked for
/// the full membership.
/// </param>
/// <param name="registration">The issuing entity's <see cref="ClientRecord"/>.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The immediate subordinates' Entity Identifiers, in the order they should
/// appear in the §8.2 response array.
/// </returns>
public delegate ValueTask<IReadOnlyList<Federation.EntityIdentifier>> ResolveSubordinateListDelegate(
    IReadOnlyList<Federation.EntityTypeIdentifier> entityTypeFilters,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves a subject's effective metadata, trust chain, and trust marks for
/// the <c>federation_resolve_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3">Federation §8.3</see>
/// when an inbound GET arrives. The library matches the request, parses the
/// <c>sub</c> / <c>anchor</c> / <c>type</c> parameters, assembles the §8.3
/// Resolve Response payload from the returned contribution, and signs it with
/// the resolver's federation signing key; the application's response to this
/// delegate is the resolution result itself.
/// </summary>
/// <remarks>
/// <para>
/// Producing the resolution — walking the subject's authority hints to the
/// requested <paramref name="trustAnchor"/>, verifying each Entity Statement
/// signature, and applying the accumulated metadata policy — is the
/// resolver application's work; the library ships the §6/§10 engines it can
/// compose but does not run them inside the endpoint. The
/// <paramref name="entityTypeFilter"/> carries the §8.3 <c>type</c>
/// parameter when present, restricting the resolved metadata to that Entity
/// Type.
/// </para>
/// <para>
/// Returning <see langword="null"/> tells the library the subject cannot be
/// resolved to the requested anchor; the endpoint then responds with HTTP
/// 404. The <paramref name="trustAnchor"/> is <see langword="null"/> when
/// the requester omitted the optional <c>anchor</c> parameter — the
/// application decides how to resolve in that case (a configured default
/// anchor, or a refusal expressed as a <see langword="null"/> return).
/// </para>
/// </remarks>
/// <param name="subject">The Entity Identifier queried via the <c>sub</c> parameter.</param>
/// <param name="trustAnchor">
/// The Trust Anchor from the <c>anchor</c> parameter, or <see langword="null"/>
/// when the requester did not supply one.
/// </param>
/// <param name="entityTypeFilter">
/// The <c>type</c> filter from the request, or <see langword="null"/> when
/// the requester asked for the subject's full resolved metadata.
/// </param>
/// <param name="registration">The resolving entity's <see cref="ClientRecord"/>.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The resolved metadata, trust chain, and trust marks, or
/// <see langword="null"/> when the subject cannot be resolved.
/// </returns>
public delegate ValueTask<Federation.ResolveResponseContribution?> ResolveSubjectTrustChainDelegate(
    Federation.EntityIdentifier subject,
    Federation.EntityIdentifier? trustAnchor,
    Federation.EntityTypeIdentifier? entityTypeFilter,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves the entity's historical (rotated and revoked) Federation Entity
/// Keys for the <c>federation_historical_keys_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.7">Federation §8.7</see>
/// when an inbound GET arrives. The library matches the request, assembles the
/// §8.7.3 Historical Keys payload (<c>iss</c>, <c>iat</c>, <c>keys</c>) from
/// the returned contribution, and signs it with the entity's federation
/// signing key; the application's response to this delegate is the historical
/// <c>keys</c> array itself.
/// </summary>
/// <remarks>
/// <para>
/// Tracking which keys the entity has rotated out of its current Entity
/// Configuration's <c>jwks</c>, and which it has revoked, is the entity
/// application's bookkeeping; the library neither stores nor invents these. It
/// only wraps the supplied keys in the signed envelope so a verifier can
/// validate a signature made with a key no longer in the live EC.
/// </para>
/// <para>
/// Returning <see langword="null"/> tells the library the entity has no
/// historical keys to publish; the endpoint then responds with HTTP 404,
/// mirroring the <c>federation_resolve_endpoint</c> null-contribution
/// contract.
/// </para>
/// </remarks>
/// <param name="registration">The publishing entity's <see cref="ClientRecord"/>.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The historical <c>keys</c> array (and any extension claims), or
/// <see langword="null"/> when the entity has no historical keys to publish.
/// </returns>
public delegate ValueTask<Federation.HistoricalKeysContribution?> ResolveHistoricalKeysDelegate(
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Processes a Relying Party's explicit client registration request at the
/// <c>federation_registration_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-12.2">Federation §12.2</see>.
/// The RP POSTs its signed Entity Configuration; the library hands the raw
/// compact JWS to this delegate, assembles the §12.2 Explicit Registration
/// Response from the returned contribution, and signs it with the OP's
/// federation signing key.
/// </summary>
/// <remarks>
/// <para>
/// The application verifies the posted Entity Configuration's signature,
/// checks its <c>aud</c> equals the OP (§3.1.4), resolves and validates the
/// RP's trust chain to a Trust Anchor the OP trusts (the library ships
/// <see cref="Federation.FederationAutomaticRegistration"/> for that
/// composition), applies metadata policy, and mints any issued client
/// credentials — then returns the resulting
/// <see cref="Federation.ExplicitRegistrationContribution"/>. The library
/// stays out of JWS parsing here (so the
/// <c>Verifiable.OAuth</c> serialization firewall is preserved): it passes
/// the body through and only builds and signs the structural response.
/// </para>
/// <para>
/// Returning <see langword="null"/> tells the library the RP cannot be
/// registered; the endpoint then responds HTTP 400.
/// </para>
/// </remarks>
/// <param name="registrationRequest">
/// The raw request body — the RP's signed Entity Configuration as a compact
/// JWS string (UTF-8 decoded from the POST body).
/// </param>
/// <param name="registration">The OP's <see cref="ClientRecord"/>.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The registration response body, or <see langword="null"/> when the RP
/// cannot be registered.
/// </returns>
public delegate ValueTask<Federation.ExplicitRegistrationContribution?> ResolveExplicitRegistrationDelegate(
    string registrationRequest,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses an OpenID AuthZEN Authorization API 1.0 Access Evaluation request
/// JSON body into the neutral <see cref="AuthZen.AccessEvaluationRequest"/>
/// information model.
/// </summary>
/// <remarks>
/// <para>
/// Required when <see cref="WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi"/>
/// is advertised. The default JSON implementation lives in
/// <c>Verifiable.OAuth.Json</c> and is wired by the application — the
/// <c>Verifiable.OAuth</c> serialization firewall keeps STJ out of the
/// library, so the request body's arbitrary <c>properties</c> / <c>context</c>
/// objects are deserialised by the application's JSON stack.
/// </para>
/// <para>
/// Return <see langword="null"/> when the body does not parse as a valid
/// Access Evaluation request; the endpoint then responds HTTP 400.
/// </para>
/// </remarks>
/// <param name="requestBody">The raw JSON request body (UTF-8 decoded from the POST body).</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<AuthZen.AccessEvaluationRequest?> ParseAccessEvaluationRequestDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses an OpenID AuthZEN Authorization API 1.0 Access Evaluations API
/// (batch) request JSON body into the neutral
/// <see cref="AuthZen.AccessEvaluationsRequest"/> information model.
/// </summary>
/// <remarks>
/// <para>
/// Required for the <c>access_evaluations_endpoint</c> when
/// <see cref="WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi"/> is
/// advertised. As with the single-evaluation parser, the default JSON
/// implementation lives in <c>Verifiable.OAuth.Json</c> and is wired by the
/// application — the <c>Verifiable.OAuth</c> serialization firewall keeps STJ
/// out of the library. The parser maps <c>options.evaluations_semantic</c>
/// through <see cref="AuthZen.AuthZenEvaluationsSemanticValues.TryParse"/>;
/// the library resolves the per-item defaults and short-circuit semantic.
/// </para>
/// <para>
/// Return <see langword="null"/> when the body does not parse as a valid
/// Access Evaluations request (including an unrecognised
/// <c>evaluations_semantic</c>); the endpoint then responds HTTP 400.
/// </para>
/// </remarks>
/// <param name="requestBody">The raw JSON request body (UTF-8 decoded from the POST body).</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<AuthZen.AccessEvaluationsRequest?> ParseAccessEvaluationsRequestDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses an OpenID AuthZEN Authorization API 1.0 Search API request JSON body
/// into the neutral <see cref="AuthZen.AccessSearchRequest"/> information
/// model. One parser serves all three search endpoints — the shape is uniform
/// (subject / action / resource / context / page); the endpoint determines
/// which dimension is being enumerated.
/// </summary>
/// <remarks>
/// As with the other AuthZEN parsers, the default JSON implementation lives in
/// <c>Verifiable.OAuth.Json</c> and is wired by the application — the
/// <c>Verifiable.OAuth</c> serialization firewall keeps STJ out of the
/// library. Return <see langword="null"/> when the body does not parse; the
/// endpoint then responds HTTP 400.
/// </remarks>
/// <param name="requestBody">The raw JSON request body (UTF-8 decoded from the POST body).</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<AuthZen.AccessSearchRequest?> ParseAccessSearchRequestDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// The Subject Search seam: enumerates the Subjects satisfying an OpenID
/// AuthZEN Authorization API 1.0 Subject Search query (§7). The application
/// owns enumeration and paging; the library owns the wire. Wiring this seam is
/// what makes the <c>search_subject_endpoint</c> active and advertised.
/// </summary>
/// <param name="request">The parsed Search request — <see cref="AuthZen.AccessSearchRequest.Subject"/> carries the searched type.</param>
/// <param name="registration">The <see cref="ClientRecord"/> serving the PDP endpoint.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<AuthZen.SubjectSearchResult> SearchSubjectsDelegate(
    AuthZen.AccessSearchRequest request,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// The Resource Search seam: enumerates the Resources satisfying an OpenID
/// AuthZEN Authorization API 1.0 Resource Search query (§7). Wiring this seam
/// is what makes the <c>search_resource_endpoint</c> active and advertised.
/// </summary>
/// <param name="request">The parsed Search request — <see cref="AuthZen.AccessSearchRequest.Resource"/> carries the searched type.</param>
/// <param name="registration">The <see cref="ClientRecord"/> serving the PDP endpoint.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<AuthZen.ResourceSearchResult> SearchResourcesDelegate(
    AuthZen.AccessSearchRequest request,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// The Action Search seam: enumerates the Actions a subject may perform on a
/// resource per an OpenID AuthZEN Authorization API 1.0 Action Search query
/// (§7). Wiring this seam is what makes the <c>search_action_endpoint</c>
/// active and advertised.
/// </summary>
/// <param name="request">The parsed Search request — <see cref="AuthZen.AccessSearchRequest.Action"/> is absent for Action Search.</param>
/// <param name="registration">The <see cref="ClientRecord"/> serving the PDP endpoint.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<AuthZen.ActionSearchResult> SearchActionsDelegate(
    AuthZen.AccessSearchRequest request,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Contributes application-supplied values to the OpenID AuthZEN Authorization
/// API 1.0 Policy Decision Point metadata document (§9.1) that the library
/// cannot derive from the endpoint chain — currently the <c>capabilities</c>
/// IANA URN list. Optional; when unset the document advertises only the PDP
/// identifier and the endpoint URLs.
/// </summary>
/// <param name="registration">The <see cref="ClientRecord"/> serving the PDP endpoint.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<AuthZen.AuthZenMetadataContribution> ContributeAuthZenMetadataDelegate(
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Contributes application-supplied values to the Shared Signals Transmitter
/// Configuration Metadata document (SSF 1.0 §7.1) that the library cannot derive
/// from the endpoint chain — delivery methods, critical subject members,
/// authorization schemes, and the default-subjects behavior. Optional; when
/// unset the document advertises only the chain-derived values.
/// </summary>
/// <param name="registration">The <see cref="ClientRecord"/> serving the Transmitter endpoint.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<Ssf.SsfTransmitterMetadataContribution> ContributeSsfTransmitterMetadataDelegate(
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Authenticates a confidential client at the token endpoint for the
/// <c>client_credentials</c> grant (RFC 6749 §4.4) — <c>client_secret_basic</c>
/// from the Authorization header, <c>client_secret_post</c> from the form
/// fields, <c>private_key_jwt</c>, or mTLS, per the deployment's policy. The
/// application owns credential storage and comparison; the endpoint rejects a
/// <see langword="false"/> with <c>401 invalid_client</c>. The grant activates
/// only when this seam is wired — an unauthenticated client-credentials grant
/// would mint tokens for anyone.
/// </summary>
/// <param name="request">The incoming request (carries the Authorization header), when available.</param>
/// <param name="fields">The form fields (carry <c>client_id</c>/<c>client_secret</c> for the POST method).</param>
/// <param name="registration">The <see cref="ClientRecord"/> the request claims to be.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<bool> ValidateClientCredentialsDelegate(
    IncomingRequest? request,
    RequestFields fields,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Validates a Token Exchange <c>subject_token</c> for the <c>urn:ietf:params:oauth:grant-type:token-exchange</c>
/// grant (RFC 8693 §2.1) and returns its accepted claims, or rejects it. The application is the
/// trust authority: it owns which issuers and keys it accepts, runs "the appropriate validation
/// procedures for the indicated token type" per
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see>, and decides
/// what the <see cref="TokenExchange.ValidatedSecurityToken"/> carries.
/// </summary>
/// <remarks>
/// <para>
/// Invoked after the endpoint has authenticated the client via
/// <see cref="ValidateClientCredentialsDelegate"/>. The <paramref name="tokenType"/> is the parsed
/// <c>subject_token_type</c> (RFC 8693 §3) telling the application how to parse
/// <paramref name="token"/> — a JWT, an access token, a SAML assertion. Any remote key fetch the
/// application needs is its own concern; the <c>Verifiable.OAuth</c> library takes no
/// <c>System.Net.*</c> dependency, so the network reach lives in the application.
/// </para>
/// <para>
/// Return <see langword="null"/> when the token is invalid, untrusted, or expired — the endpoint
/// then rejects the request with <c>invalid_grant</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 §2.2.2</see>, leaking
/// nothing about why. A non-null result is the validated subject the authorization step shapes the
/// issued token from.
/// </para>
/// </remarks>
/// <param name="token">The <c>subject_token</c> value, exactly as presented on the wire. Confidential.</param>
/// <param name="tokenType">The parsed <c>subject_token_type</c> (RFC 8693 §3) of <paramref name="token"/>.</param>
/// <param name="registration">The authenticated client requesting the exchange.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The validated subject token's claims, or <see langword="null"/> when it is not acceptable.</returns>
public delegate ValueTask<TokenExchange.ValidatedSecurityToken?> ValidateTokenExchangeTokenDelegate(
    string token,
    Client.TokenType tokenType,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Decides whether a validated Token Exchange <c>subject_token</c> may be exchanged by this client
/// for the requested target, and shapes the issued token, per
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see>. The semantic
/// permit/deny seam: which client may impersonate or act-for whom, at which <c>resource</c> /
/// <c>audience</c>, with which scope, producing which issued-token type.
/// </summary>
/// <remarks>
/// <para>
/// Invoked after <see cref="ValidateTokenExchangeTokenDelegate"/> has accepted the subject token
/// (and, for delegation, the actor token). The application owns the policy "checks as to which
/// entities are permitted to impersonate ... or receive delegations from other entities" RFC 8693
/// §2.1 names — it reads <paramref name="subjectToken"/> (the validated subject claims),
/// <paramref name="actorToken"/> (the validated actor claims, for delegation),
/// <paramref name="request"/> (the requested <c>resource</c> / <c>audience</c> / <c>scope</c> /
/// <c>requested_token_type</c>), and the authenticated <paramref name="registration"/>, and returns
/// the effective issued-token parameters in a
/// <see cref="TokenExchange.TokenExchangeAuthorization"/>.
/// </para>
/// <para>
/// <paramref name="actorToken"/> is <see langword="null"/> for IMPERSONATION (no <c>actor_token</c>
/// was presented) and non-null for DELEGATION (an <c>actor_token</c> was presented and validated).
/// For delegation the library has already enforced the structural §4.4 <c>may_act</c> check — when
/// the subject token names a <see cref="TokenExchange.ValidatedSecurityToken.MayActSubject"/>, the
/// actor's <see cref="TokenExchange.ValidatedSecurityToken.Subject"/> must equal it or the request
/// is rejected before this seam runs. The application MAY apply richer policy than that structural
/// check: it may consult its own delegation grants, scope-down the issued token, or deny an actor
/// the subject's <c>may_act</c> did not constrain. A delegated subject token's prior <c>act</c>
/// (its <see cref="TokenExchange.ValidatedSecurityToken.Act"/> chain) is preserved by the library
/// when it builds the new token's <c>act</c> claim; this seam shapes the top-level claims only.
/// </para>
/// <para>
/// Return <see langword="null"/> when the exchange is denied — for example when the authorization
/// server is "unwilling or unable to issue a token for any target service indicated by the
/// <c>resource</c> or <c>audience</c> parameters": the endpoint then answers <c>invalid_target</c>
/// per <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 §2.2.2</see>.
/// </para>
/// </remarks>
/// <param name="subjectToken">The validated <c>subject_token</c> claims accepted by the validating seam.</param>
/// <param name="actorToken">
/// The validated <c>actor_token</c> claims for a delegation exchange, or <see langword="null"/> for
/// an impersonation exchange (no <c>actor_token</c> presented).
/// </param>
/// <param name="request">The shape-validated Token Exchange request (RFC 8693 §2.1 parameters).</param>
/// <param name="registration">The authenticated client requesting the exchange.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The issued-token parameters when permitted, or <see langword="null"/> when the exchange is denied.</returns>
public delegate ValueTask<TokenExchange.TokenExchangeAuthorization?> AuthorizeTokenExchangeDelegate(
    TokenExchange.ValidatedSecurityToken subjectToken,
    TokenExchange.ValidatedSecurityToken? actorToken,
    TokenExchange.TokenExchangeRequest request,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Validates a JWT Bearer authorization-grant <c>assertion</c> for the
/// <c>urn:ietf:params:oauth:grant-type:jwt-bearer</c> grant (RFC 7523 §2.1/§3.1) and returns the
/// token shape to issue, or rejects it. The application is the trust authority: it owns which
/// issuers and keys it accepts and performs the full
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 §3</see> processing of the
/// assertion JWT before returning a <see cref="JwtBearer.JwtBearerGrant"/>.
/// </summary>
/// <remarks>
/// <para>
/// The §3 rules the application MUST enforce, in full:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <strong>Rule 1 (<c>iss</c>):</strong> the JWT MUST carry an <c>iss</c> claim that is a
///     trusted issuer, compared by Simple String Comparison (RFC 3986 §6.2.1).
///   </description></item>
///   <item><description>
///     <strong>Rule 2.A (<c>sub</c>):</strong> the JWT MUST carry a <c>sub</c> claim identifying the
///     principal access is requested for — surfaced as <see cref="JwtBearer.JwtBearerGrant.Subject"/>.
///   </description></item>
///   <item><description>
///     <strong>Rule 3 (<c>aud</c>) — the audience MUST:</strong> the JWT MUST carry an <c>aud</c>
///     claim that identifies THIS authorization server, and "the authorization server MUST reject any
///     JWT that does not contain its own identity as the intended audience." The library cannot make
///     this check — only the application knows the AS's own identity (its token endpoint URL or
///     configured audience string) — so it is delegated here and is mandatory.
///   </description></item>
///   <item><description>
///     <strong>Rules 4–5 (<c>exp</c>/<c>nbf</c>):</strong> the JWT MUST carry an <c>exp</c> and the
///     AS MUST reject an expired JWT (subject to clock skew); an <c>nbf</c>, when present, bounds the
///     earliest acceptance instant.
///   </description></item>
///   <item><description>
///     <strong>Rule 9 (signature):</strong> the JWT MUST be signed or MAC'd by the issuer and the AS
///     MUST reject an invalid signature/MAC. Any remote JWKS fetch the application needs is its own
///     concern — the <c>Verifiable.OAuth</c> library takes no <c>System.Net.*</c> dependency, so the
///     network reach lives in the application.
///   </description></item>
/// </list>
/// <para>
/// Return <see langword="null"/> when the assertion is not valid in any respect — invalid signature,
/// untrusted issuer, an <c>aud</c> that does not name this AS, an expired or not-yet-valid window, or
/// any other §3/JWT failure. The endpoint then rejects the request with <c>invalid_grant</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3.1">RFC 7523 §3.1</see> (which mandates
/// that exact error code), leaking nothing about why. A non-null result is the validated grant the
/// issued access token is shaped from.
/// </para>
/// </remarks>
/// <param name="assertion">The <c>assertion</c> value — a single JWT, exactly as presented on the wire. Confidential.</param>
/// <param name="requestedScope">The <c>scope</c> request parameter (RFC 7523 §2.1), or <see langword="null"/> when omitted.</param>
/// <param name="registration">The <see cref="ClientRecord"/> resolved for the request's tenant.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The validated grant to issue an access token for, or <see langword="null"/> when the assertion is not acceptable.</returns>
public delegate ValueTask<JwtBearer.JwtBearerGrant?> ValidateJwtBearerAssertionDelegate(
    string assertion,
    string? requestedScope,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Revokes a token at the token revocation endpoint
/// (<see href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009</see>) on behalf
/// of an authenticated client.
/// </summary>
/// <remarks>
/// <para>
/// Invoked after the endpoint has authenticated the client via
/// <see cref="ValidateClientCredentialsDelegate"/>. The application revokes the
/// presented token in its own token store and SHOULD cascade per
/// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.1">RFC 7009 §2.1</see>
/// — revoking a refresh token also invalidates the access tokens derived from it.
/// That same store is what the per-call decision seams
/// (<see cref="EvaluateAccessDelegate"/>, <see cref="LoadClientRegistrationDelegate"/>)
/// read to reject a revoked token on its next use, so a signal-driven or
/// admin-driven revocation and an RFC 7009 client-driven one converge on one
/// piece of state.
/// </para>
/// <para>
/// The operation is idempotent and returns no value: per
/// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2.2">RFC 7009 §2.2</see>
/// the endpoint answers HTTP 200 whether the token was live, already revoked, or
/// unknown — the response never reveals which. The implementation MUST scope the
/// revocation to tokens issued to <paramref name="registration"/> and treat a
/// token belonging to another client as unknown (a silent no-op).
/// </para>
/// <para>
/// <paramref name="tokenTypeHint"/> carries the RFC 7009 §2.1
/// <c>token_type_hint</c> when present — an optimization the application MAY use
/// to locate the token faster; an unrecognized hint MUST NOT cause a failure.
/// </para>
/// </remarks>
/// <param name="token">The token to revoke, exactly as presented on the wire.</param>
/// <param name="tokenTypeHint">The <c>token_type_hint</c> form value, or <see langword="null"/> when omitted.</param>
/// <param name="registration">The authenticated client whose token is being revoked.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask RevokeTokenDelegate(
    string token,
    string? tokenTypeHint,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Introspects a token at the token introspection endpoint
/// (<see href="https://www.rfc-editor.org/rfc/rfc7662">RFC 7662</see>) on behalf
/// of an authenticated protected resource, returning the token's metadata.
/// </summary>
/// <remarks>
/// <para>
/// Invoked after the endpoint has authenticated the caller via
/// <see cref="ValidateClientCredentialsDelegate"/>. The application looks the
/// presented token up in its own store and returns a
/// <see cref="Introspection.TokenIntrospectionResult"/> describing it. The same store the
/// per-call decision seams (<see cref="EvaluateAccessDelegate"/>,
/// <see cref="LoadClientRegistrationDelegate"/>) read to reject a revoked token is what
/// decides liveness here, so an introspection answer and an enforcement decision converge
/// on one piece of state.
/// </para>
/// <para>
/// Per <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 §2.2</see>
/// a token that is unknown, expired, revoked, or that this caller may not see is NOT an
/// error: the application returns <see cref="Introspection.TokenIntrospectionResult.Inactive"/>
/// (the library answers HTTP 200 with <c>{"active":false}</c> and discloses nothing
/// further). The application MUST scope its answer to what
/// <paramref name="registration"/> is entitled to learn — RFC 7662 §2.2 lets the server
/// limit, or withhold, a token's details per requesting resource.
/// </para>
/// <para>
/// <paramref name="tokenTypeHint"/> carries the RFC 7662 §2.1 <c>token_type_hint</c> when
/// present — an optimization the application MAY use to locate the token faster; an
/// unrecognized hint MUST NOT cause a failure.
/// </para>
/// </remarks>
/// <param name="token">The token to introspect, exactly as presented on the wire.</param>
/// <param name="tokenTypeHint">The <c>token_type_hint</c> form value, or <see langword="null"/> when omitted.</param>
/// <param name="registration">The authenticated protected resource making the request.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The token's metadata, or an inactive result when it is unknown or not disclosable.</returns>
public delegate ValueTask<Introspection.TokenIntrospectionResult> IntrospectTokenDelegate(
    string token,
    string? tokenTypeHint,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Issues a fresh OID4VCI 1.0 §7 <c>c_nonce</c> — an unpredictable, server-chosen challenge
/// the Wallet incorporates into the proof of possession in a subsequent Credential Request.
/// </summary>
/// <remarks>
/// Invoked by the unprotected Nonce Endpoint. The application mints the nonce and owns its
/// store, so it can later verify — at the Credential Endpoint — that a presented proof carries
/// a nonce this server issued and has not yet retired. The library owns only the wire shape
/// (<c>{"c_nonce": ...}</c> with <c>Cache-Control: no-store</c>); per OID4VCI 1.0 §7.2 the
/// nonce's format and lifetime are at the issuer's discretion, so the library prescribes neither.
/// </remarks>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>A fresh, unpredictable <c>c_nonce</c> string.</returns>
public delegate ValueTask<string> IssueCredentialNonceDelegate(
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Validates an OID4VCI 1.0 §6 Pre-Authorized Code grant and decides whether to authorize
/// access-token issuance.
/// </summary>
/// <remarks>
/// Invoked by the Pre-Authorized Code grant at the token endpoint. The application owns the
/// pre-authorized code store — populated when the Credential Offer was minted — so it is the
/// only party that can tell a wrong code from a wrong Transaction Code, decide whether a
/// Transaction Code was expected, and resolve the subject the issued Credential is about. The
/// library owns only the wire shape: it reads <c>pre-authorized_code</c> and <c>tx_code</c>
/// off the request, maps the returned <see cref="Oid4Vci.PreAuthorizedCodeDecision"/> to the
/// §6.2 token response or a §6.3 error, and mints the access token through the configured
/// token producers. Client authentication is OPTIONAL for this grant (§6.1); the seam decides
/// whether an anonymous request (no <paramref name="clientId"/>) is acceptable.
/// </remarks>
/// <param name="preAuthorizedCode">The <c>pre-authorized_code</c> the Wallet presented.</param>
/// <param name="transactionCode">
/// The <c>tx_code</c> the Wallet presented, or <see langword="null"/> when absent.
/// </param>
/// <param name="clientId">
/// The <c>client_id</c> the Wallet presented, or <see langword="null"/> when the request is
/// anonymous (permitted in this grant unless the deployment requires client authentication).
/// </param>
/// <param name="registration">The <see cref="ClientRecord"/> resolved for the request's tenant.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The application's grant-or-deny verdict.</returns>
public delegate ValueTask<Oid4Vci.PreAuthorizedCodeDecision> ValidatePreAuthorizedCodeDelegate(
    string preAuthorizedCode,
    string? transactionCode,
    string? clientId,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses an OID4VCI 1.0 §8.2 Credential Request JSON body into the neutral
/// <see cref="Oid4Vci.CredentialRequest"/> information model.
/// </summary>
/// <remarks>
/// Required when <see cref="WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint"/> is
/// advertised. The default JSON implementation lives in <c>Verifiable.OAuth.Json</c> and is
/// wired by the application — the <c>Verifiable.OAuth</c> serialization firewall keeps
/// <c>System.Text.Json</c> out of the library, so the request body's
/// <c>credential_configuration_id</c> / <c>credential_identifier</c> / <c>proofs</c> are
/// deserialised by the application's JSON stack. Return <see langword="null"/> when the body
/// does not parse as a valid Credential Request; the endpoint then responds
/// <c>400 invalid_credential_request</c>.
/// </remarks>
/// <param name="requestBody">The raw JSON request body (UTF-8 decoded from the POST body).</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<Oid4Vci.CredentialRequest?> ParseCredentialRequestDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Issues one or more OID4VCI 1.0 §8 Credentials of the same Credential Configuration on a
/// valid Credential Request, or refuses it with a §8.3.1.2 error.
/// </summary>
/// <remarks>
/// Invoked by the Credential Endpoint after the library has validated the bearer access token
/// (§8.3.1.1) and enforced the §8.2 request shape. The application owns the <c>c_nonce</c>
/// store, the set of supported Credential Configurations, and the issuer signing key, so it is
/// the only party that can verify the holder proofs in <paramref name="request"/>, mint each
/// Credential bound to its proven holder key, and tell the §8.3.1.2 error cases apart. The
/// library owns only the wire shape: it maps the returned
/// <see cref="Oid4Vci.CredentialIssuanceDecision"/> to the §8.3 Credential Response or a
/// §8.3.1.2 Credential Error Response. The <paramref name="accessToken"/> is the validated
/// access-token payload — the application reads its <c>sub</c> (the End-User the Credential is
/// about, bound by the grant) and any granted scope or <c>authorization_details</c>.
/// </remarks>
/// <param name="request">The parsed Credential Request.</param>
/// <param name="accessToken">The validated access-token claims presented at the endpoint.</param>
/// <param name="registration">The <see cref="ClientRecord"/> resolved for the request's tenant.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The application's issue-or-refuse verdict.</returns>
public delegate ValueTask<Oid4Vci.CredentialIssuanceDecision> IssueCredentialDelegate(
    Oid4Vci.CredentialRequest request,
    JwtPayload accessToken,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves what an OID4VCI 1.0 §8 Credential Request's <c>jwt</c> key proof(s) must satisfy — the
/// expected <c>c_nonce</c>, the acceptable proof-signing algorithms, and the <c>iat</c> window —
/// so the library can run the Appendix F.4 proof-validation checks BEFORE the
/// <see cref="IssueCredentialDelegate"/> seam mints.
/// </summary>
/// <remarks>
/// Wiring this seam OPTS IN to library-side §F.4 proof validation at the Credential Endpoint; when
/// it is unwired the endpoint validates no proofs and hands the whole check to
/// <see cref="IssueCredentialDelegate"/>, the established default. The application owns the
/// <c>c_nonce</c> store and its single-use retirement, so only it can answer which nonce a given
/// request's proof must echo (it reads the value off its store keyed by the validated
/// <paramref name="accessToken"/> / request) — the library compares but never stores. Returning
/// <see langword="null"/> from a wired seam means "no expectation for this request": the endpoint
/// skips library-side validation for it and defers to <see cref="IssueCredentialDelegate"/>.
/// </remarks>
/// <param name="request">The parsed Credential Request whose proofs are about to be validated.</param>
/// <param name="accessToken">The validated access-token claims presented at the endpoint.</param>
/// <param name="registration">The <see cref="ClientRecord"/> resolved for the request's tenant.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The proof expectation to enforce, or <see langword="null"/> to defer to the issuance seam.</returns>
public delegate ValueTask<Oid4Vci.CredentialProofExpectation?> ResolveCredentialProofExpectationDelegate(
    Oid4Vci.CredentialRequest request,
    JwtPayload accessToken,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Encrypts an OID4VCI 1.0 §10 (Deferred) Credential Response: the application composes the
/// JWE — using its provider's key agreement, key derivation, and AEAD delegates — to the
/// Wallet-supplied key in <paramref name="encryption"/>.
/// </summary>
/// <remarks>
/// The library owns the wire decision (§8.3/§9.2: a request carrying
/// <c>credential_response_encryption</c> MUST receive an encrypted response, media type
/// <c>application/jwt</c>, with the §8.3.1.2 <c>invalid_encryption_parameters</c> refusal when
/// that cannot happen); the application owns the §10 composition — the JWE <c>alg</c> from the
/// JWK's <c>alg</c> member, the <c>kid</c> copied when present, the <c>enc</c> from
/// <see cref="Oid4Vci.CredentialResponseEncryption.Enc"/>. Return <see langword="null"/> when
/// the parameters are unsupported (unknown <c>enc</c>, unusable key type); the endpoint then
/// refuses with <c>invalid_encryption_parameters</c>.
/// </remarks>
/// <param name="responseJson">The plaintext response body to encrypt — the §8.3/§9.2 JSON.</param>
/// <param name="encryption">The shape-validated §8.2 encryption parameters from the request.</param>
/// <param name="registration">The <see cref="ClientRecord"/> resolved for the request's tenant.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The compact JWE, or <see langword="null"/> when the parameters are unsupported.</returns>
public delegate ValueTask<string?> EncryptCredentialResponseDelegate(
    string responseJson,
    Oid4Vci.CredentialResponseEncryption encryption,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Decrypts an OID4VCI 1.0 §10 encrypted Credential Request: the application resolves its
/// decryption key (advertised in the issuer metadata's <c>credential_request_encryption.jwks</c>)
/// and returns the plaintext request JSON.
/// </summary>
/// <remarks>
/// The library owns the wire decision (a compact-JWE body on the Credential or Deferred
/// Credential Endpoint routes here; absent this seam, an encrypted request is refused); the
/// application owns the JWE decryption with its provider delegates. Return
/// <see langword="null"/> when decryption fails — the endpoint then refuses with
/// <c>invalid_credential_request</c>.
/// </remarks>
/// <param name="encryptedRequestJwt">The compact JWE request body, exactly as received.</param>
/// <param name="registration">The <see cref="ClientRecord"/> resolved for the request's tenant.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The decrypted request JSON, or <see langword="null"/> when decryption fails.</returns>
public delegate ValueTask<string?> DecryptCredentialRequestDelegate(
    string encryptedRequestJwt,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves an OID4VCI 1.0 §9 Deferred Credential Request: the application looks up its
/// deferred-transaction store by <paramref name="transactionId"/> and reports the Credentials
/// as issued, still pending, or the request as refused.
/// </summary>
/// <remarks>
/// The library validates the bearer token and the §9.1 request shape, and maps the returned
/// decision to the §9.2 200/202 responses or a §9.3 error. The application owns the
/// transaction store — only it can tell an unknown or already-consumed <c>transaction_id</c>
/// from an issuance still in flight — and §9.1 makes invalidating the <c>transaction_id</c>
/// after delivery its responsibility.
/// </remarks>
/// <param name="transactionId">The §9.1 <c>transaction_id</c> presented by the Wallet.</param>
/// <param name="accessToken">The validated access-token claims presented at the endpoint.</param>
/// <param name="registration">The <see cref="ClientRecord"/> resolved for the request's tenant.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The application's issued / pending / refused verdict.</returns>
public delegate ValueTask<Oid4Vci.DeferredCredentialDecision> ResolveDeferredCredentialDelegate(
    string transactionId,
    JwtPayload accessToken,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Processes an OID4VCI 1.0 §11.1 Notification Request — the Wallet's report on what became of
/// the Credentials identified by the notification's <c>notification_id</c>.
/// </summary>
/// <remarks>
/// The library validates the bearer token and the §11.1 request shape (including the
/// case-sensitive <c>event</c> values), and maps the returned decision to the §11.2 success or
/// the §11.3 <c>invalid_notification_id</c> error. §11 makes the notification idempotent —
/// implementations return acceptance for repeated identical calls.
/// </remarks>
/// <param name="notification">The parsed and shape-validated notification.</param>
/// <param name="accessToken">The validated access-token claims presented at the endpoint.</param>
/// <param name="registration">The <see cref="ClientRecord"/> resolved for the request's tenant.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The application's accept / reject verdict.</returns>
public delegate ValueTask<Oid4Vci.CredentialNotificationDecision> ProcessCredentialNotificationDelegate(
    Oid4Vci.CredentialNotification notification,
    JwtPayload accessToken,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves an OID4VCI 1.0 §4.1.3 by-reference Credential Offer from the application's offer
/// store by the <paramref name="offerId"/> the <c>credential_offer_uri</c> carries.
/// </summary>
/// <remarks>
/// Invoked by the unprotected Credential Offer Endpoint. The application composed the offer
/// out-of-band when it provisioned the Pre-Authorized Code (or set up the Authorization Code
/// Flow context) and owns the store keyed by the offer id embedded in the
/// <c>credential_offer_uri</c>, so only it can tell an unknown or expired id from a live one.
/// The library owns only the wire shape — the §4.1.1 JSON object served as
/// <c>application/json</c> (§4.1.3: the offer is never signed). Return <see langword="null"/>
/// when no live offer matches the id; the endpoint then responds HTTP 404.
/// </remarks>
/// <param name="offerId">The offer identifier read from the request, embedded in the <c>credential_offer_uri</c>.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The stored Credential Offer, or <see langword="null"/> when no live offer matches.</returns>
public delegate ValueTask<Oid4Vci.CredentialOffer?> ResolveCredentialOfferDelegate(
    string offerId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses an RFC 9396 <c>authorization_details</c> request parameter — a JSON array of
/// authorization details objects — into the neutral <see cref="AuthorizationDetail"/> list, the
/// generic information model that carries the §2 <c>type</c>, the §2.2 common fields, and every
/// type-specific member preserved verbatim.
/// </summary>
/// <remarks>
/// Required when the server processes <c>authorization_details</c> (RFC 9396 §2; OID4VCI 1.0
/// §5.1.1 / §6.1.1). The default JSON implementation lives in <c>Verifiable.OAuth.Json</c> and is
/// wired by the application — the <c>Verifiable.OAuth</c> serialization firewall keeps
/// <c>System.Text.Json</c> out of the library. Return <see langword="null"/> when the value is
/// not a well-formed JSON array of objects each carrying a string <c>type</c>; the endpoint then
/// responds <c>invalid_authorization_details</c>. The per-type shape checks (supported type,
/// required fields) are the library's, applied after the parse by the
/// <see cref="AuthorizationDetailTypeRegistry"/>.
/// </remarks>
/// <param name="authorizationDetailsJson">The <c>authorization_details</c> value, verbatim from the request.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<IReadOnlyList<AuthorizationDetail>?> ParseAuthorizationDetailListDelegate(
    string authorizationDetailsJson,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Decides an <c>openid_credential</c> authorization details request at the token endpoint and
/// mints the OID4VCI 1.0 §6.2 <c>credential_identifiers</c> for each granted configuration.
/// </summary>
/// <remarks>
/// Invoked by both token grants — Authorization Code (details authorized at the authorization
/// endpoint, optionally narrowed in the token request per §6.1.1) and Pre-Authorized Code
/// (details presented directly in the token request). The application owns the supported
/// Credential Configurations and the Credential Dataset store, so it alone can refuse an
/// unknown configuration and enumerate the dataset identifiers the access token will cover for
/// <paramref name="subject"/>. The library owns the wire: it parses and shape-validates the
/// parameter, enforces the §6.1.1 subset rule, and maps the returned
/// <see cref="Oid4Vci.CredentialAuthorizationDecision"/> to the §6.2 response
/// <c>authorization_details</c> or an RFC 9396 §5 <c>invalid_authorization_details</c> error.
/// </remarks>
/// <param name="requestedDetails">The shape-validated <c>openid_credential</c> authorization details.</param>
/// <param name="subject">The subject the access token is issued to.</param>
/// <param name="registration">The <see cref="ClientRecord"/> resolved for the request's tenant.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The application's grant-or-deny verdict.</returns>
public delegate ValueTask<Oid4Vci.CredentialAuthorizationDecision> ResolveCredentialAuthorizationDelegate(
    IReadOnlyList<Oid4Vci.CredentialAuthorizationDetail> requestedDetails,
    string subject,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Contributes the application-owned values of the OID4VCI 1.0 §12.2 Credential Issuer Metadata
/// document — the <c>credential_configurations_supported</c> catalog and the optional
/// <c>authorization_servers</c> / <c>display</c> / <c>batch_credential_issuance</c> — that the
/// library cannot derive from the endpoint chain.
/// </summary>
/// <remarks>
/// Required when <see cref="WellKnownCapabilityIdentifiers.Oid4VciCredentialIssuerMetadata"/> is
/// advertised: only the application knows which Credentials it issues. The library derives
/// <c>credential_issuer</c>, <c>credential_endpoint</c>, and <c>nonce_endpoint</c> itself and
/// merges this contribution over them. Return
/// <see cref="Oid4Vci.CredentialIssuerMetadataContribution.Empty"/> to emit only the derivable
/// fields (with an empty <c>credential_configurations_supported</c> object).
/// </remarks>
/// <param name="registration">The <see cref="ClientRecord"/> the metadata document describes.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<Oid4Vci.CredentialIssuerMetadataContribution> ContributeCredentialIssuerMetadataDelegate(
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Signs the assembled OID4VCI 1.0 §12.2.3 Credential Issuer Metadata as a <c>signed_metadata</c>
/// JWT. The library hands over the fully assembled metadata claim set as a
/// <see cref="JwtPayload"/> — the same values the plain document carries — and the application
/// signs it with its own key and algorithm and returns the compact JWS.
/// </summary>
/// <remarks>
/// Optional: when unset, the document carries only its plain-JSON fields; when set, the returned
/// JWT is embedded verbatim as the <c>signed_metadata</c> field, and returning
/// <see langword="null"/> omits the field. Per §12.2.3 the application's signer owns the signing
/// key and its <c>kid</c> selection — knowledge the transport-agnostic library does not hold — so
/// the JWS itself is composed here. The library supplies
/// <see cref="Oid4Vci.SignedCredentialIssuerMetadata.CreateAsync"/> as a conformant helper a seam
/// implementation SHOULD call: it sets the §12.2.3 structural claims the helper guarantees — the
/// <c>typ</c> (<c>openidvci-issuer-metadata+jwt</c>), the REQUIRED <c>sub</c> (equal to the
/// <c>credential_issuer</c> the claim set carries), and <c>iat</c> — copies every metadata
/// parameter as a top-level claim, and rejects a <c>none</c> or symmetric <c>alg</c>. A
/// <c>signed_metadata</c> claim never appears inside the JWT itself.
/// </remarks>
/// <param name="metadata">The assembled metadata claim set to sign, as a JOSE payload.</param>
/// <param name="registration">The <see cref="ClientRecord"/> the metadata document describes.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<string?> SignCredentialIssuerMetadataDelegate(
    JwtPayload metadata,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a Global Token Revocation request body
/// (<see href="https://datatracker.ietf.org/doc/draft-parecki-oauth-global-token-revocation/">draft-parecki-oauth-global-token-revocation §3</see>)
/// into the neutral <see cref="Logout.GlobalTokenRevocationRequest"/> — a single
/// <c>sub_id</c> RFC 9493 Subject Identifier.
/// </summary>
/// <remarks>
/// Required when <see cref="WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation"/>
/// is advertised. The default JSON implementation lives in
/// <c>Verifiable.OAuth.Json</c> and is wired by the application — the
/// <c>Verifiable.OAuth</c> serialization firewall keeps <c>System.Text.Json</c>
/// out of the library. Return <see langword="null"/> when the body does not parse
/// as a valid request (no <c>sub_id</c>, or an unreadable Subject Identifier); the
/// endpoint then responds HTTP 400.
/// </remarks>
/// <param name="requestBody">The raw JSON request body (UTF-8 decoded from the POST body).</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<Logout.GlobalTokenRevocationRequest?> ParseGlobalTokenRevocationRequestDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Revokes all of a subject's tokens for a Global Token Revocation command
/// (<see href="https://datatracker.ietf.org/doc/draft-parecki-oauth-global-token-revocation/">draft-parecki-oauth-global-token-revocation §3</see>)
/// on behalf of an authenticated client.
/// </summary>
/// <remarks>
/// <para>
/// Invoked after the endpoint authenticates the client and parses the
/// <c>sub_id</c>. The application MUST revoke all of the subject's refresh
/// tokens, invalidate its access tokens where feasible, and require
/// re-authentication before issuing new ones. This is the global-logout fan-out
/// drop-out: the application performs the revocation against the same token store
/// the per-call decision seams (<see cref="EvaluateAccessDelegate"/>,
/// <see cref="LoadClientRegistrationDelegate"/>) read, and — when it runs a Shared
/// Signals Transmitter — MAY emit a CAEP <c>session-revoked</c> event on
/// completion. The library owns the wire and the status-code mapping; the
/// application owns the revocation and any signal emission. There is deliberately
/// no library "orchestrator" object — the orchestration is this delegate.
/// </para>
/// <para>
/// The returned <see cref="Logout.GlobalTokenRevocationOutcome"/> selects the
/// response: <c>Initiated</c> → 204, <c>SubjectNotFound</c> → 404,
/// <c>Forbidden</c> → 403, <c>Unprocessable</c> → 422.
/// </para>
/// </remarks>
/// <param name="subId">The RFC 9493 Subject Identifier whose tokens are to be revoked.</param>
/// <param name="registration">The authenticated client issuing the command.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<Logout.GlobalTokenRevocationOutcome> RevokeSubjectTokensDelegate(
    Verifiable.Core.SecurityEvents.SubjectIdentifier subId,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Terminates the End-User's authentication session for an RP-Initiated Logout
/// (<see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OIDC RP-Initiated Logout 1.0</see>).
/// Invoked by the end-session endpoint after it has verified the <c>id_token_hint</c>
/// and validated the <c>post_logout_redirect_uri</c>.
/// </summary>
/// <remarks>
/// The application ends the session identified by <paramref name="sessionId"/> (the ID
/// Token's <c>sid</c>) for <paramref name="subject"/> in its session store and SHOULD
/// revoke that session's tokens — the same store the per-call decision seams read.
/// Idempotent. Back-Channel Logout (a later slice) composes the registered-RP fan-out
/// after this. <paramref name="sessionId"/> is <see langword="null"/> when the
/// <c>id_token_hint</c> carried no <c>sid</c> (terminate by subject).
/// </remarks>
/// <param name="subject">The subject whose session is being terminated (the hint's <c>sub</c>).</param>
/// <param name="sessionId">The session identifier (<c>sid</c>) from the id_token_hint, or <see langword="null"/>.</param>
/// <param name="registration">The client (tenant) the logout request belongs to.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask TerminateSessionDelegate(
    string subject,
    string? sessionId,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Terminates a session identified only by an opaque <c>logout_hint</c> — the
/// sessionless RP-Initiated Logout path
/// (<see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OIDC RP-Initiated Logout 1.0 §3</see>),
/// taken when the request carries a <c>logout_hint</c> but no <c>id_token_hint</c>.
/// </summary>
/// <remarks>
/// Per §3 the value and meaning of <c>logout_hint</c> are at the OP's discretion (it may
/// be an email, phone number, username, or an RP-session identifier), so the library does
/// not interpret it: it drops out to the application, which resolves the hint to a session
/// (or sessions) and ends it. Wiring this delegate is what enables the sessionless branch
/// of the end-session endpoint; when it is unset the endpoint still requires an
/// <c>id_token_hint</c>. Idempotent.
/// </remarks>
/// <param name="logoutHint">The opaque <c>logout_hint</c> value, verbatim from the request.</param>
/// <param name="registration">The client (tenant) the logout request belongs to.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask TerminateSessionByHintDelegate(
    string logoutHint,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Fans a terminated session out to every registered RP as an OIDC Back-Channel Logout
/// (<see href="https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel Logout 1.0</see>),
/// invoked by the end-session endpoint <em>after</em> <see cref="TerminateSessionDelegate"/>
/// has ended the local session.
/// </summary>
/// <remarks>
/// There is deliberately no library "orchestrator": this seam IS the fan-out. The
/// application enumerates the sessions/RPs the logout touches (its own session→RP store —
/// the library does not hold that list), builds a Logout Token per RP with
/// <see cref="Logout.BackChannelLogout.BuildLogoutTokenAsync"/> (audience = that RP's
/// identifier, the supplied <paramref name="subject"/>/<paramref name="sessionId"/>), and
/// POSTs each to the RP's <c>backchannel_logout_uri</c>. Wiring this seam is what advertises
/// <c>backchannel_logout_supported</c>. Best-effort and idempotent; a delivery failure to one
/// RP MUST NOT abort the others.
/// </remarks>
/// <param name="subject">The subject whose session was terminated (the verified hint's <c>sub</c>).</param>
/// <param name="sessionId">The terminated session id (<c>sid</c>), or <see langword="null"/> when the hint carried none.</param>
/// <param name="registration">The client (tenant) the logout request belongs to.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask DeliverBackChannelLogoutDelegate(
    string subject,
    string? sessionId,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Signs the assembled OpenID AuthZEN Authorization API 1.0 PDP metadata as a
/// <c>signed_metadata</c> JWT (§9.1). The library hands over the fully
/// assembled metadata claim set as a <see cref="Verifiable.JCose.JwtPayload"/>
/// (the PDP identifier, the chain-resolved endpoint URLs, and any
/// <c>capabilities</c>); the application signs it with its own key and
/// algorithm — e.g. via <c>Verifiable.JCose</c>
/// <see cref="Verifiable.JCose.Jose.SignAsync{TJwtPart}(TJwtPart, TJwtPart, Verifiable.JCose.JwtPartEncoder{TJwtPart}, Verifiable.JCose.EncodeDelegate, Verifiable.Cryptography.PrivateKeyMemory, System.Buffers.MemoryPool{byte}, System.Threading.CancellationToken)"/> —
/// and returns the compact JWS. The application MUST add the spec-required
/// <c>iss</c> claim (the PDP identifier, available as
/// <c>policy_decision_point</c> in <paramref name="metadata"/>).
/// </summary>
/// <remarks>
/// The claim set is a <see cref="Verifiable.JCose.JwtPayload"/> — the JOSE
/// payload leaf — rather than a raw dictionary, so it carries its role (a JWT
/// payload, not a header) in the type and composes directly with the JCose
/// signing surface. Optional: when unset, the document carries only its
/// plain-JSON fields; when set, the returned JWT is embedded verbatim as the
/// <c>signed_metadata</c> field. Returning <see langword="null"/> omits the
/// field. Signing is delegated rather than performed in-library because the
/// signing key and algorithm are deployment choices and this is an OPTIONAL
/// feature; the library imposes no key-management surface for it.
/// </remarks>
/// <param name="metadata">The assembled metadata claim set to sign, as a JOSE payload.</param>
/// <param name="registration">The <see cref="ClientRecord"/> serving the PDP endpoint.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<string?> SignAuthZenMetadataDelegate(
    Verifiable.JCose.JwtPayload metadata,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Contributes application-supplied values to the OAuth 2.0 Protected Resource
/// Metadata document (RFC 9728 §2) that the library cannot derive from the
/// endpoint chain — the authorization servers, scopes, bearer methods,
/// human-readable fields, and feature booleans. Optional; when unset the
/// document advertises only the derived <c>resource</c> and <c>jwks_uri</c>.
/// </summary>
/// <param name="registration">The <see cref="ClientRecord"/> serving the protected resource.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<ProtectedResource.ProtectedResourceMetadataContribution> ContributeProtectedResourceMetadataDelegate(
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Signs the assembled OAuth 2.0 Protected Resource Metadata as a
/// <c>signed_metadata</c> JWT (RFC 9728 §2.2). The library hands over the
/// fully assembled metadata claim set as a
/// <see cref="Verifiable.JCose.JwtPayload"/> — the same values the plain
/// document carries — and the application signs it with its own key and
/// algorithm and returns the compact JWS. The application MUST add the
/// spec-required <c>iss</c> claim denoting the party attesting to the claims.
/// </summary>
/// <remarks>
/// Optional: when unset, the document carries only its plain-JSON fields; when
/// set, the returned JWT is embedded verbatim as the <c>signed_metadata</c>
/// field, and returning <see langword="null"/> omits the field. Per §2.2 a
/// <c>signed_metadata</c> claim never appears inside the JWT itself. Signing
/// is delegated rather than performed in-library because the signing key and
/// algorithm are deployment choices and this is an OPTIONAL feature.
/// </remarks>
/// <param name="metadata">The assembled metadata claim set to sign, as a JOSE payload.</param>
/// <param name="registration">The <see cref="ClientRecord"/> serving the protected resource.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<string?> SignProtectedResourceMetadataDelegate(
    Verifiable.JCose.JwtPayload metadata,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// The Policy Decision Point seam: evaluates a parsed OpenID AuthZEN
/// Authorization API 1.0 Access Evaluation request and returns the
/// <see cref="AuthZen.AccessEvaluationDecision"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is where the application's authorization policy runs — the library
/// owns the wire (parse, dispatch, serialise) but never the decision. Wire
/// to a policy engine (Cedar, OPA/Rego, a rules table, an upstream PDP) or a
/// bespoke evaluator. The decision is serialised to the AuthZEN
/// <c>{ "decision": &lt;bool&gt; }</c> response by the library.
/// </para>
/// <para>
/// Fail-closed: the seam returns a decision, not an error. A policy that
/// cannot reach a permit returns
/// <see cref="AuthZen.AccessEvaluationDecision.Deny"/>.
/// </para>
/// </remarks>
/// <param name="request">The parsed Access Evaluation request.</param>
/// <param name="registration">The <see cref="ClientRecord"/> serving the PDP endpoint.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<AuthZen.AccessEvaluationDecision> EvaluateAccessDelegate(
    AuthZen.AccessEvaluationRequest request,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Makes the application's authorization decision for an authorization-endpoint request,
/// after the End-User has been authenticated and the library's own checks (PKCE, redirect
/// URI, scope, and the temporal <c>max_age</c> recency requirement) have passed. The
/// application receives the requested and established facts in
/// <paramref name="evaluation"/> — plus the full per-request <paramref name="context"/> —
/// and may permit or deny on <em>any</em> of them: the requested
/// <see cref="AuthorizationRequestEvaluation.RequestedAcrValues"/> against the
/// <see cref="AuthorizationRequestEvaluation.EstablishedAcr"/> (an assurance-level
/// comparison only the deployment can make), resource-owner consent, or deployment policy.
/// </summary>
/// <remarks>
/// <para>
/// Returns a decision, not an error — mirroring <see cref="EvaluateAccessDelegate"/>. A
/// denial carries an <see cref="AuthorizationDenialReason"/> the library maps to the OAuth
/// 2.0 Authorization Error Response code (<c>unmet_authentication_requirements</c> for an
/// unsatisfied <c>acr</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9470#section-5">RFC 9470 §5</see>,
/// <c>access_denied</c> for a consent/policy refusal per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>),
/// delivered to the client as a redirect. When this delegate is not wired the authorization
/// server applies no additional decision at this point — the achieved <c>acr</c> is still
/// conveyed in the issued tokens and the resource server's step-up challenge remains the
/// backstop.
/// </para>
/// </remarks>
/// <param name="evaluation">The requested and established authorization-request facts.</param>
/// <param name="registration">The client registration the request belongs to.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The application's permit-or-deny verdict.</returns>
public delegate ValueTask<AuthorizationRequestDecision> EvaluateAuthorizationRequestDelegate(
    AuthorizationRequestEvaluation evaluation,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
