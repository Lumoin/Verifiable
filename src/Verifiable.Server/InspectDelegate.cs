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
/// The library default is <see cref="DefaultInspector.NoOpAsync"/>.
/// Applications wire their own delegate to record audit trails, emit
/// OpenTelemetry events, capture replay-determinism tuples (see the
/// design doc §2.4), or forward SSF/CAEP signals.
/// </para>
/// <para>
/// Exceptions thrown from the delegate propagate to the dispatcher and
/// fail the request — inspectors that should never fail a request must
/// catch and swallow internally.
/// </para>
/// </remarks>
/// <param name="stage">The pipeline stage being inspected.</param>
/// <param name="context">The per-request context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask InspectDelegate(
    InspectionStage stage,
    ExchangeContext context,
    CancellationToken cancellationToken);
