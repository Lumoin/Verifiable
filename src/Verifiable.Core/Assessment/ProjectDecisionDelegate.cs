using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Assessment
{
    /// <summary>
    /// Transforms an <see cref="AssessmentResult"/> into a deployment-defined
    /// projection. Pure function — callers consume the result; no
    /// side-effects on the underlying decision.
    /// </summary>
    /// <typeparam name="TProjection">
    /// The projection target type. Typically a serialisable record matching
    /// the downstream consumer's contract: an audit-row schema, an
    /// outgoing-message envelope, a redacted summary safe for telemetry,
    /// or an HTTP response body.
    /// </typeparam>
    /// <param name="decision">The decision being projected.</param>
    /// <param name="cancellationToken">
    /// Token to monitor for cancellation requests. Honoured by projections
    /// that perform async lookups (e.g. enrichment from a downstream
    /// catalogue); pure transformations typically run to completion.
    /// </param>
    /// <returns>The projection of <paramref name="decision"/>.</returns>
    /// <remarks>
    /// <para>
    /// Peer to <see cref="RecordDecisionDelegate"/>. Record observes
    /// without transforming; Project transforms without observing.
    /// Compose both when both are needed:
    /// </para>
    /// <code>
    /// var projection = await projector(decision, ct).ConfigureAwait(false);
    /// await sink.PublishAsync(projection, ct).ConfigureAwait(false);
    /// </code>
    /// </remarks>
    public delegate ValueTask<TProjection> ProjectDecisionDelegate<TProjection>(
        AssessmentResult decision,
        CancellationToken cancellationToken);
}
