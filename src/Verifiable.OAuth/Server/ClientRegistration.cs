using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.OAuth.Oid4Vp;

namespace Verifiable.OAuth.Server;

/// <summary>
/// A registered client and its allowed capabilities, redirect URIs, scopes,
/// and associated metadata.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ClientRegistration"/> is pure data — it carries no delegates and
/// performs no I/O. All effectful operations (loading, saving, CIMD fetch) are
/// performed by the delegates in <see cref="AuthorizationServerOptions"/>.
/// </para>
/// <para>
/// The <see cref="TenantId"/> is the opaque identifier the application uses to
/// distinguish tenants. The library has no opinion on what it means at the wire
/// layer — the application's <see cref="AuthorizationServerOptions.ExtractTenantIdAsync"/>
/// delegate decides whether tenants are identified by URL path segment, subdomain,
/// Host header, mTLS certificate subject, or any combination of these. The same
/// <see cref="TenantId"/> value flows through every storage delegate, scoping
/// per-tenant flow records and registration lookups.
/// </para>
/// <para>
/// <see cref="ClientMetadataUri"/> is non-null when the client uses Client ID Metadata
/// Documents (CIMD) — the <see cref="ClientId"/> is the CIMD document URL and the server
/// fetches it on demand via <see cref="AuthorizationServerOptions.ResolveClientMetadataAsync"/>.
/// When null, all registration data is stored directly in this record.
/// </para>
/// <para>
/// <see cref="FederationEntityId"/> is non-null when the client participates in
/// OpenID Federation. The server resolves the trust chain from this entity identifier
/// using <see cref="WellKnownPaths.OpenIdFederation"/> before accepting assertions
/// from this client.
/// </para>
/// <para>
/// <strong>Signing keys</strong>
/// </para>
/// <para>
/// <see cref="SigningKeys"/> carries the tenant's signing-key inventory indexed by
/// <see cref="KeyUsageContext"/>. Each entry is a <see cref="SigningKeySet"/> with
/// rotation-aware slots — current, incoming, retiring, historical. A tenant that
/// issues both OAuth tokens and verifiable credentials carries two entries
/// (<see cref="KeyUsageContext.AccessTokenIssuance"/> and
/// <see cref="KeyUsageContext.CredentialIssuance"/>), each with its own rotation
/// lifecycle. Tenants participating in only one protocol carry one entry.
/// </para>
/// <para>
/// Library call sites that sign retrieve a <see cref="KeyId"/> via the
/// <see cref="SelectSigningKeyDelegate"/> (defaulting to the first entry in
/// <c>Current</c> when no delegate is configured), then materialise the key
/// through <see cref="AuthorizationServerOptions.SigningKeyResolver"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("ClientRegistration ClientId={ClientId} TenantId={TenantId}")]
public sealed record ClientRegistration
{
    /// <summary>
    /// The client identifier. May be an opaque string, a CIMD URL, or a DID.
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The tenant identifier under which this registration lives. Opaque to the
    /// library; meaningful to the application's tenant resolver and storage layer.
    /// Set at registration time and used by every storage delegate to scope
    /// per-tenant lookups and writes.
    /// </summary>
    public required TenantId TenantId { get; init; }

    /// <summary>
    /// The capabilities this client is allowed to use.
    /// Only capabilities present here will have active endpoints.
    /// </summary>
    public required ImmutableHashSet<ServerCapabilityName> AllowedCapabilities { get; init; }

    /// <summary>
    /// The redirect URIs this client may use.
    /// Exact string matching is enforced per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see>.
    /// </summary>
    public required ImmutableHashSet<Uri> AllowedRedirectUris { get; init; }

    /// <summary>
    /// The scopes this client may request.
    /// </summary>
    public required ImmutableHashSet<string> AllowedScopes { get; init; }

    /// <summary>
    /// Per-token-type lifetimes keyed by token type name.
    /// Keys are typically <c>"access_token"</c>, <c>"refresh_token"</c>, <c>"id_token"</c>.
    /// </summary>
    public required IReadOnlyDictionary<string, TimeSpan> TokenLifetimes { get; init; }

    /// <summary>
    /// The tenant's signing-key inventory indexed by protocol usage context.
    /// Each entry holds the rotation-aware key set for one usage — current,
    /// incoming, retiring, and historical <see cref="KeyId"/> values.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A registration participating in OAuth access-token issuance has an entry keyed
    /// on <see cref="KeyUsageContext.AccessTokenIssuance"/>. A registration issuing
    /// OpenID Connect ID tokens has an entry keyed on
    /// <see cref="KeyUsageContext.IdTokenIssuance"/>. A registration issuing
    /// verifiable credentials has an entry keyed on
    /// <see cref="KeyUsageContext.CredentialIssuance"/>. An OID4VP verifier has
    /// an entry keyed on <see cref="KeyUsageContext.JarSigning"/>. A
    /// registration may carry multiple entries for tenants participating in
    /// multiple protocols.
    /// </para>
    /// <para>
    /// The library retrieves <see cref="KeyId"/> values from this structure via
    /// <see cref="AuthorizationServerOptions.SelectSigningKey"/> (or its default)
    /// when signing, and publishes them via
    /// <see cref="AuthorizationServerOptions.BuildJwksDocumentAsync"/> when
    /// serving JWKS.
    /// </para>
    /// </remarks>
    public required IReadOnlyDictionary<KeyUsageContext, SigningKeySet> SigningKeys { get; init; }

    /// <summary>
    /// The canonical URL at which this tenant's authorization server is reachable.
    /// Appears as the <c>iss</c> claim in tokens, as the <c>issuer</c> field in
    /// discovery metadata, and as the base for endpoint URIs published via
    /// discovery. <see langword="null"/> for deployments that derive the issuer
    /// per-request from the reverse proxy's forwarded host instead of declaring
    /// it at registration time.
    /// </summary>
    /// <remarks>
    /// Read by <see cref="DefaultIssuerResolver"/> when
    /// <see cref="AuthorizationServerOptions.ResolveIssuerAsync"/> is not set.
    /// Applications supplying their own resolver may ignore this field.
    /// </remarks>
    public Uri? IssuerUri { get; init; }

    /// <summary>
    /// The URI of the Client ID Metadata Document when the client uses CIMD.
    /// <see langword="null"/> for pre-registered clients.
    /// When non-null, <see cref="ClientId"/> equals this URI's string representation.
    /// </summary>
    public Uri? ClientMetadataUri { get; init; }

    /// <summary>
    /// The OpenID Federation entity identifier when this client participates in federation.
    /// <see langword="null"/> for clients that do not use federation.
    /// </summary>
    public Uri? FederationEntityId { get; init; }

    /// <summary>
    /// The <c>response_uri</c> to which the Wallet POSTs the Authorization Response
    /// in OID4VP flows. <see langword="null"/> for non-OID4VP registrations.
    /// </summary>
    public Uri? ResponseUri { get; init; }

    /// <summary>
    /// The Verifier's client metadata for OID4VP flows, including the JWKS carrying
    /// the ephemeral P-256 exchange public key for ECDH-ES response encryption.
    /// <see langword="null"/> for non-OID4VP registrations.
    /// </summary>
    public VerifierClientMetadata? ClientMetadata { get; init; }

    /// <summary>
    /// Application-defined metadata passed through the context bag to all delegates.
    /// Carries tenant identifiers, DID anchors, attestation roots, or any other
    /// context the application needs without coupling the library to specific types.
    /// </summary>
    public IReadOnlyDictionary<string, object> RegistrationMetadata { get; init; } =
        FrozenDictionary<string, object>.Empty;


    /// <summary>
    /// Returns <see langword="true"/> when this client is allowed to use
    /// <paramref name="capability"/>.
    /// </summary>
    public bool IsCapabilityAllowed(ServerCapabilityName capability) =>
        AllowedCapabilities.Contains(capability);


    /// <summary>
    /// Returns the token lifetime for <paramref name="tokenType"/>, or
    /// <see langword="null"/> if no explicit lifetime is configured for that type.
    /// </summary>
    public TimeSpan? GetTokenLifetime(string tokenType)
    {
        ArgumentNullException.ThrowIfNull(tokenType);
        return TokenLifetimes.TryGetValue(tokenType, out TimeSpan lifetime)
            ? lifetime
            : null;
    }


    /// <summary>
    /// Returns the default signing <see cref="KeyId"/> for
    /// <paramref name="usage"/> — the first entry in the corresponding
    /// <see cref="SigningKeySet.Current"/> list. Used by the library's signing
    /// paths when no <see cref="SelectSigningKeyDelegate"/> is configured.
    /// </summary>
    /// <exception cref="KeyNotFoundException">
    /// Thrown when <see cref="SigningKeys"/> has no entry for
    /// <paramref name="usage"/>, indicating the tenant is not configured for
    /// this protocol role.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the entry's <see cref="SigningKeySet.Current"/> list is empty.
    /// </exception>
    public KeyId GetDefaultSigningKeyId(KeyUsageContext usage)
    {
        if(!SigningKeys.TryGetValue(usage, out SigningKeySet? set))
        {
            throw new KeyNotFoundException(
                $"Registration '{ClientId}' has no signing keys configured for usage context '{usage}'.");
        }

        if(set.Current.IsEmpty)
        {
            throw new InvalidOperationException(
                $"Registration '{ClientId}' has an empty Current list for usage context '{usage}'.");
        }

        return set.Current[0];
    }
}
