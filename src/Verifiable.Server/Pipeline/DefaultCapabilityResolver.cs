using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.Server.Pipeline;

/// <summary>
/// Library default backing for the capability-resolution seam: returns
/// <see cref="IRegistrationRecord.AllowedCapabilities"/> unchanged, so every
/// registration capability is active for every request unless the application
/// supplies a custom delegate that attenuates them.
/// </summary>
[DebuggerDisplay("DefaultCapabilityResolver")]
public static class DefaultCapabilityResolver
{
    /// <summary>
    /// Returns the registration's full
    /// <see cref="IRegistrationRecord.AllowedCapabilities"/> set.
    /// </summary>
    public static ValueTask<IReadOnlySet<CapabilityIdentifier>> ResolveAsync(
        IRegistrationRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);

        return ValueTask.FromResult(registration.AllowedCapabilities);
    }
}
