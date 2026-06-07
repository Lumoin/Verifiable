using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Assessment
{
    /// <summary>
    /// Library-shipped defaults for
    /// <see cref="RecordDecisionDelegate"/> and
    /// <see cref="ProjectDecisionDelegate{TProjection}"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The recording default is a no-op so wiring the slot is free; the
    /// projection default is the identity projection returning the
    /// <see cref="AssessmentResult"/> itself, useful when downstream
    /// consumers expect a projection-shaped call but don't actually
    /// transform.
    /// </para>
    /// </remarks>
    public static class DefaultDecisionObservers
    {
        /// <summary>
        /// Default <see cref="RecordDecisionDelegate"/> — no-op. Wiring this
        /// is equivalent to leaving the slot unfilled but keeps the
        /// composition explicit.
        /// </summary>
        public static ValueTask Record(
            AssessmentResult decision,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(decision);
            cancellationToken.ThrowIfCancellationRequested();

            return ValueTask.CompletedTask;
        }


        /// <summary>
        /// Identity <see cref="ProjectDecisionDelegate{TProjection}"/> over
        /// <see cref="AssessmentResult"/>. Returns the decision unchanged.
        /// </summary>
        public static ValueTask<AssessmentResult> ProjectIdentity(
            AssessmentResult decision,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(decision);
            cancellationToken.ThrowIfCancellationRequested();

            return ValueTask.FromResult(decision);
        }
    }
}
