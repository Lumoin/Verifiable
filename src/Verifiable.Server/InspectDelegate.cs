using Verifiable.Core;
namespace Verifiable.Server;

/// <summary>
/// Invoked by the dispatcher at well-defined stages of request processing.
/// Inspection is observational — implementations record, measure, or
/// forward; they do not change request behaviour or short-circuit
/// dispatch. See <see cref="InspectionStage"/> for the stage discriminator.
/// </summary>
/// <remarks>
/// <para>
/// The library default is <see cref="Pipeline.DefaultInspector.NoOpAsync"/>.
/// Applications wire their own delegate to record audit trails, emit
/// OpenTelemetry events, capture replay-determinism tuples (see the
/// design doc §2.4), or forward SSF/CAEP signals.
/// </para>
/// <para>
/// Incoming and matched inspection exceptions propagate before commitment. Outgoing response
/// inspection runs after the handler completes on every dispatch; its exceptions are recorded
/// on the request Activity and the response returns as built. Registration observer diagnostics
/// are isolated by their emitter and receive a detached, empty context.
/// </para>
/// </remarks>
/// <param name="stage">The pipeline stage being inspected.</param>
/// <param name="context">The per-request context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask InspectDelegate(
    InspectionStage stage,
    ExchangeContext context,
    CancellationToken cancellationToken);
