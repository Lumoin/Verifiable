using Verifiable.Core;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Loads the symmetric key material for a specific <see cref="KeyId"/>.
/// Parallel to <see cref="ServerSigningKeyResolverDelegate"/> for
/// asymmetric signing keys — pure byte-loading with no rotation or
/// selection logic.
/// </summary>
/// <remarks>
/// <para>
/// The kid is chosen at the call site by
/// <see cref="Keys.SelectHmacKeyDelegate"/> (issuance) or extracted from
/// the wire artefact (validation), then passed here for material lookup.
/// Returning <see langword="null"/> indicates the kid is unknown to the
/// application's key store.
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
public delegate ValueTask<SymmetricKey?> ResolveServerHmacKeyDelegate(
    KeyId kid,
    TenantId tenantId,
    ExchangeContext context,
    CancellationToken cancellationToken);
