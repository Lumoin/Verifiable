using System.Diagnostics;
using Verifiable.Core.Automata;
using Verifiable.OAuth.Oid4Vp.States;

namespace Verifiable.OAuth.Oid4Vp.Session;

/// <summary>
/// The result of a single <see cref="Oid4VpFlowSession.StepAsync"/> call.
/// </summary>
/// <param name="Outcome">Whether the step transitioned, halted, or faulted.</param>
/// <param name="State">
/// The state after the step. When <see cref="Outcome"/> is
/// <see cref="Oid4VpStepOutcome.Transitioned"/> this is the new state and must be
/// persisted together with <see cref="StepCount"/>. For <see cref="Oid4VpStepOutcome.Halted"/>
/// or <see cref="Oid4VpStepOutcome.Faulted"/> this is the unchanged input state.
/// </param>
/// <param name="Accepted">
/// <see langword="true"/> when <paramref name="State"/> satisfies the accept predicate,
/// i.e., the flow reached <see cref="PresentationVerifiedState"/>.
/// </param>
/// <param name="StepCount">
/// The total number of successful transitions including this one. Persist alongside
/// <see cref="State"/> and supply to the next <see cref="Oid4VpFlowSession.StepAsync"/>
/// call as <c>stepCount</c>.
/// </param>
/// <param name="TraceEntry">
/// The trace entry emitted by the automaton for this step. Never <see langword="null"/> —
/// even halted and faulted steps emit one entry.
/// </param>
/// <param name="FaultException">
/// The exception thrown by the transition delegate when
/// <see cref="Outcome"/> is <see cref="Oid4VpStepOutcome.Faulted"/>;
/// <see langword="null"/> otherwise.
/// </param>
[DebuggerDisplay("Oid4VpStepResult Outcome={Outcome} Step={StepCount} Accepted={Accepted}")]
public sealed record Oid4VpStepResult(
    Oid4VpStepOutcome Outcome,
    OAuthFlowState State,
    bool Accepted,
    int StepCount,
    TraceEntry<OAuthFlowState, OAuthFlowInput> TraceEntry,
    Exception? FaultException = null);
