using Verifiable.Core;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Server.Keys;

/// <summary>
/// Selects which <see cref="KeyId"/> to use for a given HMAC operation.
/// Parallel to <see cref="SelectSigningKeyDelegate"/> for asymmetric
/// signing keys. The library's default selector returns the first entry
/// in <see cref="KeySet.Current"/>; specific use cases (algorithm
/// selection, per-recipient pinning) override.
/// </summary>
/// <param name="keySet">The candidate set; selector returns one kid from it.</param>
/// <param name="purpose">
/// The MAC purpose. Currently informational (e.g. <c>"DpopNonce"</c>);
/// future use may dispatch on it.
/// </param>
/// <param name="tenantId">Tenant for per-tenant selection policies.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The kid to use, or <see langword="null"/> when the application has no
/// current key available (configuration / rotation gap). Callers treat
/// null as an operational failure.
/// </returns>
public delegate ValueTask<KeyId?> SelectHmacKeyDelegate(
    KeySet keySet,
    string purpose,
    TenantId tenantId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Returns the current HMAC <see cref="KeySet"/> for the given tenant.
/// Used by issuance paths to feed <see cref="SelectHmacKeyDelegate"/>
/// with the candidate set, by validation paths to check slot membership
/// before accepting a presented kid, and by JWKS publication.
/// </summary>
public delegate ValueTask<KeySet> GetHmacKeySetDelegate(
    TenantId tenantId,
    ExchangeContext context,
    CancellationToken cancellationToken);
