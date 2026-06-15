using System.Diagnostics;
using Verifiable.Core;

namespace Verifiable.Server.Pipeline;

/// <summary>
/// Library default backing for
/// <see cref="ServerIntegration.InspectAsync"/>: a no-op that
/// completes synchronously. Deployments that don't need inspection wire
/// this explicitly to satisfy <see cref="ServerIntegration.Validate"/>.
/// </summary>
[DebuggerDisplay("DefaultInspector")]
public static class DefaultInspector
{
    /// <summary>
    /// Returns <see cref="ValueTask.CompletedTask"/> without observing the
    /// stage.
    /// </summary>
    public static ValueTask NoOpAsync(
        InspectionStage stage,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        ValueTask.CompletedTask;
}
