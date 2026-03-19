using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Loads a <see cref="ClientRegistration"/> from the backing store by tenant identifier.
/// </summary>
/// <remarks>
/// <para>
/// Called at the start of every request after the dispatcher has resolved the tenant
/// via <see cref="AuthorizationServerOptions.ExtractTenantIdAsync"/>. The implementation
/// looks up the registration in whatever per-tenant store it maintains.
/// </para>
/// <para>
/// Return <see langword="null"/> when the registration is not found — the handler returns
/// <c>invalid_client</c> without leaking whether the identifier exists. The
/// <paramref name="context"/> carries request-scoped data the implementation can read
/// for finer-grained decisions (e.g., region routing, feature flags).
/// </para>
/// </remarks>
public delegate ValueTask<ClientRegistration?> LoadClientRegistrationDelegate(
    TenantId tenantId,
    RequestContext context,
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
    RequestContext context,
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
    RequestContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves a private signing key by identifier. The signing key is scoped to the
/// registration that owns it; the registration is already tenant-scoped, so this
/// delegate does not take a tenant parameter directly.
/// </summary>
/// <remarks>
/// Return <see langword="null"/> when the key is unavailable — the handler returns
/// <c>server_error</c> without leaking key store details.
/// </remarks>
public delegate ValueTask<PrivateKeyMemory?> ServerSigningKeyResolverDelegate(
    string keyId,
    RequestContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves a public verification key by identifier. The verification key is scoped
/// to the registration that publishes it; the registration is already tenant-scoped,
/// so this delegate does not take a tenant parameter directly.
/// </summary>
public delegate ValueTask<PublicKeyMemory?> ServerVerificationKeyResolverDelegate(
    string keyId,
    RequestContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Serializes a <see cref="PublicKeyMemory"/> to a JWKS JSON string for the JWKS endpoint.
/// </summary>
public delegate ValueTask<string> SerializeJwksDelegate(
    PublicKeyMemory publicKey,
    RequestContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Builds the <see cref="JwksDocument"/> to serve at the JWKS endpoint for the given
/// client registration.
/// </summary>
/// <remarks>
/// <para>
/// The delegate receives the full <see cref="ClientRegistration"/> and the per-request
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
/// The <see cref="ClientRegistration"/> whose JWKS is being served.
/// </param>
/// <param name="context">
/// The per-request context bag carrying whatever the ASP.NET skin chose to surface.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The <see cref="JwksDocument"/> to serialize and return in the HTTP response body.
/// </returns>
public delegate ValueTask<JwksDocument> BuildJwksDocumentDelegate(
    ClientRegistration registration,
    RequestContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Determines whether the given <see cref="ClientRegistration"/> is allowed to use
/// <paramref name="capability"/> for the current request.
/// </summary>
/// <remarks>
/// Return <see langword="false"/> to have the handler respond with
/// <c>unauthorized_client</c>. The default when this delegate is null is to check
/// <see cref="ClientRegistration.IsCapabilityAllowed"/> only.
/// </remarks>
public delegate ValueTask<bool> IsCapabilityAllowedDelegate(
    ClientRegistration registration,
    ServerCapabilityName capability,
    RequestContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Fetches and validates a Client ID Metadata Document for CIMD clients.
/// </summary>
/// <remarks>
/// Return <see langword="null"/> when the document cannot be fetched or fails
/// validation. Caching with appropriate TTL is the responsibility of the implementation.
/// </remarks>
public delegate ValueTask<ClientRegistration?> ResolveClientMetadataDelegate(
    Uri clientMetadataUri,
    RequestContext context,
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
    RequestContext context,
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
/// afterwards. The contribution is strictly additive — the library's base fields
/// take precedence over any duplicate keys in the returned dictionary.
/// </para>
/// </remarks>
/// <param name="registration">The <see cref="ClientRegistration"/> the discovery document describes.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The contributed discovery fields keyed by their JSON property name.</returns>
public delegate ValueTask<IReadOnlyDictionary<string, object>> ContributeDiscoveryFieldsDelegate(
    ClientRegistration registration,
    RequestContext context,
    CancellationToken cancellationToken);
