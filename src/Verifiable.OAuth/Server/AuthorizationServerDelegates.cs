using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;

using Verifiable.OAuth.Server.Metadata;
using Verifiable.OAuth.Server.Routing;
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
/// Persists an <see cref="OAuthFlowState"/> and its step count to durable storage
/// under the given correlation key, scoped by tenant.
/// </summary>
/// <remarks>
/// <para>
/// Called after every successful PDA transition. Must be idempotent.
/// </para>
/// <para>
/// The <paramref name="tenantId"/> scopes the storage write to the tenant the request
/// belongs to. Storage layers key records by <c>(tenantId, correlationKey)</c> so that
/// flow state from one tenant cannot be loaded under another. The PDA state record
/// itself does not carry tenant — tenant isolation is enforced at this storage boundary,
/// not at the state layer.
/// </para>
/// <para>
/// The <paramref name="correlationKey"/> is the protocol handle that will arrive
/// at the next endpoint — for example the <c>request_uri</c> opaque token for
/// PAR-based flows, the authorization <c>code</c> for the token endpoint, the
/// <c>device_code</c> for device authorization polling, or the <c>auth_req_id</c>
/// for CIBA. The application stores the state under this key so that
/// <see cref="LoadServerFlowStateDelegate"/> can retrieve it directly without
/// any secondary index or mapping table.
/// </para>
/// </remarks>
public delegate ValueTask SaveServerFlowStateDelegate(
    TenantId tenantId,
    string correlationKey,
    OAuthFlowState state,
    int stepCount,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Deletes a previously-saved flow state, scoped by tenant.
/// </summary>
/// <remarks>
/// <para>
/// Required for protocol paths that rotate or invalidate state — most
/// notably refresh-token rotation per
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.2.2">RFC 9700 §2.2.2</see>.
/// On a successful refresh exchange the AS invalidates the presented
/// refresh token by calling this delegate against the token's flow id;
/// the application's lambda removes the secondary-index entry and the
/// flow record from storage.
/// </para>
/// <para>
/// Implementations are idempotent: a delete against an unknown
/// <paramref name="correlationKey"/> is a no-op, not an error. The
/// dispatcher relies on this for clean retry semantics.
/// </para>
/// </remarks>
public delegate ValueTask DeleteServerFlowStateDelegate(
    TenantId tenantId,
    string correlationKey,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Loads an <see cref="OAuthFlowState"/> and step count from durable storage by
/// correlation key, scoped by tenant.
/// </summary>
/// <remarks>
/// <para>
/// The <paramref name="tenantId"/> scopes the storage read to the tenant the request
/// belongs to — a load attempt under one tenant must never return a record persisted
/// under another. The library does not enforce this at the state layer; the storage
/// implementation is responsible for keying records by <c>(tenantId, correlationKey)</c>
/// or otherwise refusing cross-tenant reads.
/// </para>
/// <para>
/// The <paramref name="correlationKey"/> is extracted from the inbound request by
/// <see cref="AuthorizationServer"/> — it is whatever the protocol's natural handle
/// is at this endpoint: a <c>request_uri</c> token, an authorization <c>code</c>,
/// a <c>device_code</c>, a <c>state</c> value, or an <c>auth_req_id</c>.
/// </para>
/// <para>
/// Returns <c>(null, 0)</c> when no state is found for the given <paramref name="tenantId"/>
/// and <paramref name="correlationKey"/> pair.
/// </para>
/// </remarks>
public delegate ValueTask<(OAuthFlowState? State, int StepCount)> LoadServerFlowStateDelegate(
    TenantId tenantId,
    string correlationKey,
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
/// <param name="entityTypeFilter">
/// The <c>entity_type</c> filter from the request, or <see langword="null"/>
/// when the requester asked for the full membership.
/// </param>
/// <param name="registration">The issuing entity's <see cref="ClientRecord"/>.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The immediate subordinates' Entity Identifiers, in the order they should
/// appear in the §8.2 response array.
/// </returns>
public delegate ValueTask<IReadOnlyList<Federation.EntityIdentifier>> ResolveSubordinateListDelegate(
    Federation.EntityTypeIdentifier? entityTypeFilter,
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
