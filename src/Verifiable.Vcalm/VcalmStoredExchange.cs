using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Vcalm.Exchange;

namespace Verifiable.Vcalm;

/// <summary>
/// The application-stored record of a W3C VCALM 1.0 §3.6 exchange instance — the data the engine
/// persists across vcapi messages and reports through the §3.6.6 get-exchange-state endpoint, beyond
/// the PDA <c>FlowState</c> the flow-state seam stores. The application owns the store behind the
/// <see cref="VcalmIntegration"/> exchange seams.
/// </summary>
/// <remarks>
/// <para>
/// The exchange's lifecycle <see cref="State"/> and <see cref="Sequence"/> live on the PDA state and
/// are mirrored here for the §3.6.6 view. <see cref="StepResults"/> is the reserved
/// <c>variables.results</c> object (§3.6: "Results from each step of an exchange"), keyed by step
/// name, each value the verbatim JSON of the result the engine accepted at that step (a
/// <c>verifiablePresentation</c> the holder presented). <see cref="VariablesJson"/> is the verbatim
/// <c>variables</c> the §3.6.3 creator supplied.
/// </para>
/// <para>
/// B.3 / B.4: the application owns retention and size of this record; the library writes it and reads
/// it back through the seams but never decides storage policy.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmStoredExchange ExchangeId={ExchangeId} State={State} Sequence={Sequence}")]
public sealed record VcalmStoredExchange
{
    /// <summary>The §3.6 <c>{localExchangeId}</c> the exchange is addressed by.</summary>
    public required string ExchangeId { get; init; }

    /// <summary>The §3.6 internal flow identifier the PDA <c>FlowState</c> is persisted under.</summary>
    public required string FlowId { get; init; }

    /// <summary>The §3.6.6 <c>state</c> — the exchange lifecycle status.</summary>
    public required VcalmExchangeState State { get; init; }

    /// <summary>The §3.6.6 <c>sequence</c> — the per-exchange message sequence number (0 on creation).</summary>
    public required int Sequence { get; init; }

    /// <summary>
    /// The §3.6.6 <c>expires</c> — the verbatim XML Schema <c>dateTimeStamp</c> the exchange expires
    /// at, or <see langword="null"/> when the deployment did not bound it.
    /// </summary>
    public string? Expires { get; init; }

    /// <summary>
    /// The §3.6.6 <c>step</c> — the current step in the exchange, or <see langword="null"/> for a
    /// single-step present-or-offer exchange that names no step graph.
    /// </summary>
    public string? Step { get; init; }

    /// <summary>
    /// The §3.6.6 <c>variables.results</c> object — per step name, the verbatim JSON of the result the
    /// engine accepted (a presented <c>verifiablePresentation</c>). Empty until the holder presents.
    /// </summary>
    public ImmutableDictionary<string, string> StepResults { get; init; } =
        ImmutableDictionary<string, string>.Empty;

    /// <summary>
    /// The verbatim §3.6.3 <c>variables</c> JSON the creator supplied (excluding <c>results</c>), or
    /// <see langword="null"/> when none was supplied.
    /// </summary>
    public string? VariablesJson { get; init; }

    /// <summary>
    /// The §3.6.6 <c>lastError</c> ProblemDetail, or <see langword="null"/> when the exchange has not
    /// errored. Set when a presented message is rejected (§3.6 4xx).
    /// </summary>
    public VcalmProblemDetail? LastError { get; init; }


    /// <summary>
    /// Projects the §3.6.6 exchange-state view from a loaded exchange PDA <c>FlowState</c> and its
    /// persisted step count. The §3.6.6 <c>sequence</c> is the step count (§3.6.6: "Set to 0 on
    /// creation", incremented per vcapi message); the <c>state</c>, <c>step</c>, <c>variables.results</c>
    /// (the verified <c>verifiablePresentation</c>), and <c>lastError</c> are read off the state record.
    /// Returns <see langword="null"/> for a non-exchange flow state (a type mismatch, never expected).
    /// </summary>
    /// <param name="state">The loaded exchange flow state.</param>
    /// <param name="stepCount">The persisted PDA step count.</param>
    public static VcalmStoredExchange? FromState(FlowState state, int stepCount)
    {
        ArgumentNullException.ThrowIfNull(state);

        //§3.6.6 sequence: "Set to 0 on creation", incremented per vcapi participation message. The PDA
        //counts the create transition (sentinel → pending) as its first step, so the §3.6.6 sequence is
        //the step count minus that create step — 0 at creation, 1 after the first §3.6.5 POST, and so on.
        int sequence = stepCount > 0 ? stepCount - 1 : 0;

        return state switch
        {
            VcalmExchangePendingState pending => new VcalmStoredExchange
            {
                ExchangeId = pending.ExchangeId,
                FlowId = pending.FlowId,
                State = VcalmExchangeState.Pending,
                Sequence = sequence,
                Expires = pending.Expires,
                Step = null,
                VariablesJson = pending.VariablesJson
            },

            VcalmExchangeActiveState active => new VcalmStoredExchange
            {
                ExchangeId = active.ExchangeId,
                FlowId = active.FlowId,
                State = VcalmExchangeState.Active,
                Sequence = sequence,
                Expires = active.Expires,
                Step = active.StepName,
                StepResults = active.StepResults,
                VariablesJson = active.VariablesJson
            },

            VcalmExchangeCompleteState complete => new VcalmStoredExchange
            {
                ExchangeId = complete.ExchangeId,
                FlowId = complete.FlowId,
                State = VcalmExchangeState.Complete,
                Sequence = sequence,
                Expires = complete.Expires,
                Step = complete.ResultStepName,
                //§3.6.6 variables.results: the full per-step accumulation. The single-step path also
                //carries its one verified presentation under ResultStepName, folded in here so the view
                //is identical whether the result came from a single step or a multi-step walk.
                StepResults = ComposeResults(complete),
                VariablesJson = complete.VariablesJson
            },

            VcalmExchangeInvalidState invalid => new VcalmStoredExchange
            {
                ExchangeId = invalid.ExchangeId,
                FlowId = invalid.FlowId,
                State = VcalmExchangeState.Invalid,
                Sequence = sequence,
                Expires = invalid.Expires,
                Step = invalid.StepName,
                StepResults = invalid.StepResults,
                VariablesJson = invalid.VariablesJson,
                LastError = VcalmProblemDetail.Error(invalid.ErrorType, invalid.ErrorTitle, invalid.ErrorDetail)
            },

            _ => null
        };
    }


    //§3.6.6 variables.results for a completed exchange: the accumulated per-step results, with the
    //single-step verified presentation (ResultStepName / VerifiablePresentationJson) folded in when the
    //accumulation does not already carry that step. A single-step exchange records its result only
    //through the ResultStepName pair (StepResults stays empty there), so this fold keeps the view
    //correct for both the single-step and multi-step shapes.
    private static ImmutableDictionary<string, string> ComposeResults(VcalmExchangeCompleteState complete)
    {
        ImmutableDictionary<string, string> results = complete.StepResults;
        if(complete.ResultStepName is { } step
            && complete.VerifiablePresentationJson is { } vp
            && !results.ContainsKey(step))
        {
            //§3.6.6 result value shape: { verifiablePresentation : <vp> }. The single-step verified
            //presentation carries only the bare VP; wrap it into the result-object shape the multi-step
            //accumulation already uses so the §3.6.6 view is uniform across both paths.
            results = results.SetItem(step, Exchange.VcalmExchangeResponseWriter.BuildStepPresentationResult(vp));
        }

        return results;
    }
}
