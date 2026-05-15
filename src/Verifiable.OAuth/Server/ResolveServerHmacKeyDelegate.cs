using Verifiable.OAuth.Server.Keys;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Loads the HMAC key material for a specific kid. Parallel to
/// <see cref="ServerSigningKeyResolverDelegate"/> for asymmetric signing
/// keys — pure byte-loading with no rotation or selection logic.
/// </summary>
/// <remarks>
/// <para>
/// The kid is chosen at the call site by <see cref="SelectHmacKeyDelegate"/>
/// (issuance) or extracted from the wire artefact (validation), then passed
/// here for material lookup. Returning <see langword="null"/> indicates the
/// kid is unknown to the application's key store; the caller treats this
/// as an operational failure (issuance) or a verification failure
/// (validation).
/// </para>
/// <para>
/// Implementations MUST cache in-process on the hot path; nonce issuance
/// and validation invoke this delegate per request.
/// </para>
/// <para>
/// The <paramref name="tenantId"/> parameter enables per-tenant key
/// isolation; applications that don't need it ignore the value.
/// </para>
/// </remarks>
public delegate ValueTask<HmacKey?> ResolveServerHmacKeyDelegate(
    string kid,
    TenantId tenantId,
    RequestContext context,
    CancellationToken cancellationToken);
