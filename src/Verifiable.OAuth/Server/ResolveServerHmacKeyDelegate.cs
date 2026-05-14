using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Resolves a server-held HMAC key for nonce issuance or validation,
/// parallel to <see cref="ServerSigningKeyResolverDelegate"/> for
/// asymmetric signing keys.
/// </summary>
/// <remarks>
/// <para>
/// When <paramref name="kid"/> is <see langword="null"/>, the resolver
/// returns the current key chosen for new issuance and the kid that
/// identifies it. When <paramref name="kid"/> is non-null, the resolver
/// looks up the key with that specific identifier — used during
/// validation where the kid was extracted from a presented artefact.
/// </para>
/// <para>
/// Returns <see langword="null"/> when the kid is unknown (key was rotated
/// out, kid was never issued by this AS, etc.). The caller treats this
/// as a validation failure.
/// </para>
/// <para>
/// Implementations MUST cache in-process on the hot path; the library's
/// nonce issuance and validation paths invoke this delegate per request.
/// </para>
/// </remarks>
public delegate ValueTask<HmacKeyResolution?> ResolveServerHmacKeyDelegate(
    string? kid,
    TenantId tenantId,
    RequestContext context,
    CancellationToken cancellationToken);
