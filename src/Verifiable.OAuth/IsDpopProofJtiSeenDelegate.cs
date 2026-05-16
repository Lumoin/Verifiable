using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Returns <see langword="true"/> when <paramref name="jti"/> has been
/// previously seen by this resource server within its replay window per
/// RFC 9449 §11.1. The replay tracker scope is RS-side and independent of
/// the AS-side JTI tracker used at the token endpoint — proof <c>jti</c>
/// values can repeat across receivers because each receiver tracks them
/// against its own window.
/// </summary>
public delegate ValueTask<bool> IsDpopProofJtiSeenDelegate(
    string jti,
    RequestContext context,
    CancellationToken cancellationToken);
