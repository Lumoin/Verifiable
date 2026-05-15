namespace Verifiable.OAuth.Server.Keys;

/// <summary>
/// Selects which kid to use for a given HMAC operation. Parallel to
/// <see cref="SelectSigningKeyDelegate"/> for asymmetric signing keys.
/// The library's default selector returns the kid of the first entry in
/// <see cref="KeySet{TKey}.Current"/>; specific use cases (algorithm
/// selection, per-recipient pinning) override.
/// </summary>
/// <param name="keySet">The candidate set; selector returns one kid from it.</param>
/// <param name="purpose">
/// The MAC purpose. Currently informational (e.g. <c>"DpopNonce"</c>);
/// future use may dispatch on it. The library passes a stable string
/// constant per call site.
/// </param>
/// <param name="tenantId">Tenant for per-tenant selection policies.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The kid to use for this HMAC operation, or <see langword="null"/> when
/// the application has no current key available (a configuration / rotation
/// gap). Callers treat null as an operational failure.
/// </returns>
public delegate ValueTask<string?> SelectHmacKeyDelegate(
    KeySet<HmacKey> keySet,
    string purpose,
    TenantId tenantId,
    RequestContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Returns the current HMAC keyset for the given tenant. Used by issuance
/// paths to feed <see cref="SelectHmacKeyDelegate"/> with the candidate
/// set, and by validation paths to check slot membership before accepting
/// a presented kid.
/// </summary>
public delegate ValueTask<KeySet<HmacKey>> GetHmacKeySetDelegate(
    TenantId tenantId,
    RequestContext context,
    CancellationToken cancellationToken);
