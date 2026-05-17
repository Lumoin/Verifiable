using System.Diagnostics;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Library default backing for
/// <see cref="AuthorizationServerIntegration.InspectAsync"/>: a no-op that
/// completes synchronously. Deployments that don't need inspection wire
/// this explicitly to satisfy <see cref="AuthorizationServerIntegration.Validate"/>.
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
        RequestContext context,
        CancellationToken cancellationToken) =>
        ValueTask.CompletedTask;
}
