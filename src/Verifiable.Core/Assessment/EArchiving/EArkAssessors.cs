using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Assessment.EArchiving;

/// <summary>
/// The assessors that turn an E-ARK package's claim set into one conclusion.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The conclusion is a fold over the claims and nothing else.</strong> No assessor here looks at the
/// package, the manifest or the preservation metadata: by the time one runs, every question the requirement
/// catalogues ask has already been answered by a rule and recorded as a claim. That is what makes the
/// conclusion auditable — anyone holding the claim set can recompute it — and what keeps the requirements'
/// meaning in one place instead of two.
/// </para>
/// <para>
/// <strong>The assessment carries a snapshot of the evidence it judged.</strong> A claim issue result hands its
/// claims over as an <see cref="System.Collections.Generic.IList{T}"/>, which the issuer fills and the caller
/// keeps a reference to; an assessment that stored that same list would let a holder add or remove a claim
/// after the conclusion was folded, so re-running the fold over the attached claim set would contradict the
/// stored boolean. Every assessment built here therefore copies the claim set at the fold boundary and attaches
/// the copy read-only. Nothing else about the claim issue result changes, and no claim is copied — the claims
/// themselves are immutable, so the snapshot is of the list and not of its members.
/// </para>
/// <para>
/// A caller whose policy differs writes its own <see cref="AssessDelegateAsync"/> over the same claim set; the
/// two below are the readings the specifications themselves state.
/// </para>
/// </remarks>
public static class EArkAssessors
{
    /// <summary>The version this assessor stamps its results with.</summary>
    private static string AssessorVersion { get; } = "1.0.0";


    /// <summary>
    /// The reading the requirement catalogues state: a package conforms when no requirement it was judged
    /// against failed.
    /// </summary>
    /// <param name="claimsToAssess">The claims the rule lists issued.</param>
    /// <param name="assessorId">Identifier for the assessor.</param>
    /// <param name="creationTimestamp">The instant the assessment is stamped with, from the caller's time source.</param>
    /// <param name="traceId">Tracing identifier.</param>
    /// <param name="spanId">Span identifier.</param>
    /// <param name="baggage">Additional context.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The assessment.</returns>
    /// <remarks>
    /// <para>
    /// A deviation from a recommendation does not make a package non-conformant, which is what the
    /// specification means by stating a requirement as a SHOULD, and a requirement whose condition the package
    /// never triggered was never binding. Only a failed MUST — and a claim generation that did not run to
    /// completion — makes the answer no.
    /// </para>
    /// <para>
    /// <strong>An undecided claim does not stop this assessor from reading conformance.</strong> A rule the
    /// caller gave nothing to judge reports itself inconclusive with
    /// <see cref="EArkClaimReason.SubjectNotSupplied"/>, and this fold does not look at it: a package assessed
    /// against three of the catalogue's requirements and no more reads as conformant here, because none of the
    /// three failed. That is the specifications' own reading — a requirement nobody judged the package against
    /// is not a requirement the package broke — and it is deliberately NOT a statement that the catalogue was
    /// answered.
    /// </para>
    /// <para>
    /// <strong>A caller that needs the catalogue answered asks a different question.</strong>
    /// <see cref="FullyAssessedPackageAssessorAsync"/> is the same fold with the undecided claims counted, so
    /// its boolean says both "nothing failed" and "nothing was left unjudged";
    /// <see cref="CountReason(ClaimIssueResult, EArkClaimReason)"/> over
    /// <see cref="EArkClaimReason.SubjectNotSupplied"/> reads how much was left unjudged without folding at
    /// all; and the claim set on <see cref="AssessmentResult.ClaimsResult"/> carries every requirement's own
    /// answer. A caller that treats this assessor's <see langword="true"/> as "the package was fully checked"
    /// is reading something the fold does not state.
    /// </para>
    /// </remarks>
    public static ValueTask<AssessmentResult> ConformantPackageAssessorAsync(
        ClaimIssueResult claimsToAssess,
        string assessorId,
        DateTime creationTimestamp,
        string? traceId,
        string? spanId,
        IReadOnlyDictionary<string, string>? baggage,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claimsToAssess);
        cancellationToken.ThrowIfCancellationRequested();

        bool conformant = claimsToAssess.IsComplete && CountOutcome(claimsToAssess, ClaimOutcome.Failure) == 0;

        return ValueTask.FromResult(Build(conformant, claimsToAssess, assessorId, creationTimestamp, traceId, spanId, baggage));
    }


    /// <summary>
    /// The stricter reading a caller wants when it has supplied every document the catalogues constrain: a
    /// package passes when nothing failed <em>and</em> no rule was left undecided for want of a subject.
    /// </summary>
    /// <param name="claimsToAssess">The claims the rule lists issued.</param>
    /// <param name="assessorId">Identifier for the assessor.</param>
    /// <param name="creationTimestamp">The instant the assessment is stamped with, from the caller's time source.</param>
    /// <param name="traceId">Tracing identifier.</param>
    /// <param name="spanId">Span identifier.</param>
    /// <param name="baggage">Additional context.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>The assessment.</returns>
    /// <remarks>
    /// The difference from <see cref="ConformantPackageAssessorAsync"/> is exactly the claims whose reason is
    /// <see cref="EArkClaimReason.SubjectNotSupplied"/>. A deviation from a recommendation still does not fail
    /// the package here — that would be reading a SHOULD as a MUST, which no policy can do on the
    /// specification's behalf.
    /// </remarks>
    public static ValueTask<AssessmentResult> FullyAssessedPackageAssessorAsync(
        ClaimIssueResult claimsToAssess,
        string assessorId,
        DateTime creationTimestamp,
        string? traceId,
        string? spanId,
        IReadOnlyDictionary<string, string>? baggage,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claimsToAssess);
        cancellationToken.ThrowIfCancellationRequested();

        bool conformant = claimsToAssess.IsComplete
            && CountOutcome(claimsToAssess, ClaimOutcome.Failure) == 0
            && CountReason(claimsToAssess, EArkClaimReason.SubjectNotSupplied) == 0;

        return ValueTask.FromResult(Build(conformant, claimsToAssess, assessorId, creationTimestamp, traceId, spanId, baggage));
    }


    /// <summary>Counts the claims of a claim set carrying one outcome.</summary>
    /// <param name="claimsToAssess">The claims the rule lists issued.</param>
    /// <param name="outcome">The outcome to count.</param>
    /// <returns>How many claims carry it.</returns>
    public static int CountOutcome(ClaimIssueResult claimsToAssess, ClaimOutcome outcome)
    {
        ArgumentNullException.ThrowIfNull(claimsToAssess);

        int count = 0;
        for(int i = 0; i < claimsToAssess.Claims.Count; ++i)
        {
            if(claimsToAssess.Claims[i].Outcome == outcome)
            {
                ++count;
            }
        }

        return count;
    }


    /// <summary>Counts the claims of a claim set that reached their outcome for one reason.</summary>
    /// <param name="claimsToAssess">The claims the rule lists issued.</param>
    /// <param name="reason">The reason to count.</param>
    /// <returns>How many claims carry it. A claim whose context is not an E-ARK one is not counted.</returns>
    public static int CountReason(ClaimIssueResult claimsToAssess, EArkClaimReason reason)
    {
        ArgumentNullException.ThrowIfNull(claimsToAssess);

        int count = 0;
        for(int i = 0; i < claimsToAssess.Claims.Count; ++i)
        {
            if(claimsToAssess.Claims[i].Context is EArkClaimContext context && context.Reason == reason)
            {
                ++count;
            }
        }

        return count;
    }


    /// <summary>Builds the assessment result both assessors return.</summary>
    /// <param name="isSuccess">What the fold concluded.</param>
    /// <param name="claimsToAssess">The claims the conclusion was folded from.</param>
    /// <param name="assessorId">Identifier for the assessor.</param>
    /// <param name="creationTimestamp">The instant the assessment is stamped with.</param>
    /// <param name="traceId">Tracing identifier.</param>
    /// <param name="spanId">Span identifier.</param>
    /// <param name="baggage">Additional context.</param>
    /// <returns>The assessment, carrying a read-only snapshot of the claim set its conclusion was folded from.</returns>
    /// <remarks>
    /// The snapshot is taken here, at the one boundary both assessors pass through, so the conclusion and the
    /// evidence attached to it are fixed together. Everything else the claim issue result states — its
    /// identifiers, its completion status, its rule counts, its issuing context — is carried across unchanged.
    /// </remarks>
    private static AssessmentResult Build(
        bool isSuccess,
        ClaimIssueResult claimsToAssess,
        string assessorId,
        DateTime creationTimestamp,
        string? traceId,
        string? spanId,
        IReadOnlyDictionary<string, string>? baggage)
    {
        return new(
            IsSuccess: isSuccess,
            AssessorId: assessorId,
            AssessmentId: Guid.NewGuid().ToString(),
            CorrelationId: claimsToAssess.CorrelationId,
            AssessorVersion: AssessorVersion,
            CreationTimestampInUtc: creationTimestamp,
            AssessmentContext: new AssessmentContext(),
            ClaimsResult: claimsToAssess with { Claims = SnapshotOf(claimsToAssess.Claims) },
            TraceId: traceId,
            SpanId: spanId,
            Baggage: baggage);

        //The same claims, in the same order, copied out of the list the claim issuer filled and its caller
        //still holds, and handed on in a list that refuses to be changed. The claims themselves are immutable,
        //so this snapshots the container and nothing more.
        static IList<Claim> SnapshotOf(IList<Claim> claims)
        {
            List<Claim> copy = new(claims.Count);
            for(int i = 0; i < claims.Count; ++i)
            {
                copy.Add(claims[i]);
            }

            return copy.AsReadOnly();
        }
    }
}
