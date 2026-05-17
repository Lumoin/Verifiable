using System.Diagnostics;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Library default backing for
/// <see cref="AuthorizationServerIntegration.ResolveCapabilitiesAsync"/>:
/// returns <see cref="ClientRecord.AllowedCapabilities"/> unchanged, so
/// every registration capability is active for every request unless the
/// application supplies a custom delegate that attenuates them.
/// </summary>
[DebuggerDisplay("DefaultCapabilityResolver")]
public static class DefaultCapabilityResolver
{
    /// <summary>
    /// Returns the registration's full <see cref="ClientRecord.AllowedCapabilities"/>
    /// set as a <see cref="IReadOnlySet{T}"/>.
    /// </summary>
    public static ValueTask<IReadOnlySet<ServerCapabilityName>> ResolveAsync(
        ClientRecord registration,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        return ValueTask.FromResult<IReadOnlySet<ServerCapabilityName>>(registration.AllowedCapabilities);
    }
}
