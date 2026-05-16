using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Records that <paramref name="jti"/> was seen at this resource server,
/// retaining it until <paramref name="expiresAt"/> so subsequent
/// presentations within the freshness window can be detected and
/// rejected per RFC 9449 §11.1.
/// </summary>
/// <remarks>
/// Implementations are idempotent. The validator calls this once per
/// accepted proof after <see cref="IsDpopProofJtiSeenDelegate"/> returns
/// <see langword="false"/>; storage layers SHOULD treat a duplicate
/// insert as a no-op rather than an error.
/// </remarks>
public delegate ValueTask PersistDpopProofJtiDelegate(
    string jti,
    DateTimeOffset expiresAt,
    RequestContext context,
    CancellationToken cancellationToken);
