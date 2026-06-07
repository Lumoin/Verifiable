using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Library default backing for
/// <see cref="AuthorizationServerIntegration.ResolveSubjectIdentifierAsync"/>:
/// returns the end-user identifier unchanged (the OIDC <c>subject_type=public</c>
/// behaviour per OIDC Core §8.1). Pairwise deployments wire a custom
/// delegate that computes the per-sector hash.
/// </summary>
[DebuggerDisplay("DefaultSubjectIdentifierResolver")]
public static class DefaultSubjectIdentifierResolver
{
    /// <summary>
    /// Returns <paramref name="endUserId"/> unchanged.
    /// </summary>
    public static ValueTask<string> PublicAsync(
        string endUserId,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(endUserId);
}
