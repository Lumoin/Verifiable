using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Assessment
{
    /// <summary>
    /// Pure-observation hook invoked with the <see cref="AssessmentResult"/>
    /// every assessor produces. Implementations record / forward the decision
    /// (audit log, telemetry pipeline, status cache, message bus) but MUST
    /// NOT influence the assessment outcome — callers do not consume any
    /// return value.
    /// </summary>
    /// <param name="decision">
    /// The decision being observed — carries the assessor identity, the
    /// underlying <see cref="ClaimIssueResult"/>, and tracing metadata.
    /// </param>
    /// <param name="cancellationToken">
    /// Token to monitor for cancellation requests. Implementations may
    /// honour cancellation for long-running observation paths (remote
    /// audit sinks), but rapid local sinks typically run to completion.
    /// </param>
    /// <remarks>
    /// <para>
    /// Cross-cutting peer to the federation-scoped
    /// <c>RecordTrustChainStatusDelegate</c>: this delegate operates on
    /// the post-assessment <see cref="AssessmentResult"/> across every
    /// assessor in the library — federation, OAuth, OID4VP, DID — so a
    /// single observation surface can record every decision the system
    /// makes. Federation deployments that wire only this delegate skip
    /// the federation-specific record hook; deployments that want both
    /// surfaces wire one into the other.
    /// </para>
    /// </remarks>
    public delegate ValueTask RecordDecisionDelegate(
        AssessmentResult decision,
        CancellationToken cancellationToken);
}
