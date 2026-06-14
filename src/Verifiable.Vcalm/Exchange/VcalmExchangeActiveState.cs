using System.Collections.Immutable;
using System.Diagnostics;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// The W3C VCALM 1.0 §3.6 exchange in progress: the engine has issued a §3.4 verifiable presentation
/// request to the holder (it replied with <c>verifiablePresentationRequest</c> on a prior §3.6.5 vcapi
/// message) and is awaiting the holder's <c>verifiablePresentation</c>. The §3.6.6 state is
/// <c>active</c>.
/// </summary>
/// <remarks>
/// <para>
/// §3.6: "If the object includes verifiablePresentationRequest, then the exchange is not yet complete
/// and some additional information is requested." The state carries the anti-replay
/// <see cref="Challenge"/> and <see cref="Domain"/> the engine bound the request to, so the next
/// §3.6.5 message's presented <c>verifiablePresentation</c> is verified against them — the same
/// challenge / domain binding the §3.3.2 verifier enforces.
/// </para>
/// <para>
/// <see cref="StepName"/> names the step this active request belongs to (§3.6.6 <c>step</c>); the
/// verified presentation is stored under it in the §3.6.6 <c>variables.results</c>. A single-step
/// present-or-offer exchange uses one fixed step name; a later §3.6.1 workflow surface can advance the
/// step pointer across a multi-step graph.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmExchangeActiveState FlowId={FlowId} ExchangeId={ExchangeId} Step={StepName}")]
public sealed record VcalmExchangeActiveState: FlowState
{
    /// <summary>The §3.6 <c>{localExchangeId}</c> the exchange is addressed by.</summary>
    public required string ExchangeId { get; init; }

    /// <summary>The §3.6.3 <c>expires</c> the exchange was created with, verbatim, or <see langword="null"/> when unbounded.</summary>
    public string? Expires { get; init; }

    /// <summary>The verbatim §3.6.3 <c>variables</c> JSON the creator supplied, or <see langword="null"/> when none.</summary>
    public string? VariablesJson { get; init; }

    /// <summary>The §3.6.6 <c>step</c> the current verifiable presentation request belongs to.</summary>
    public required string StepName { get; init; }

    /// <summary>
    /// The anti-replay <c>challenge</c> the engine bound the issued verifiable presentation request to
    /// (§3.4.1). The holder's presented <c>verifiablePresentation</c> proof MUST echo it, and the
    /// engine verifies the presentation against it.
    /// </summary>
    public required string Challenge { get; init; }

    /// <summary>
    /// The <c>domain</c> the engine bound the issued verifiable presentation request to (§3.4.1) — the
    /// verifier target the holder binds the presentation to. The engine verifies the presentation
    /// against it.
    /// </summary>
    public required string Domain { get; init; }

    /// <summary>
    /// The §3.4 query JSON the engine sent in the active step's verifiable presentation request, MINUS
    /// its <c>challenge</c> / <c>domain</c> (those are bound separately in <see cref="Challenge"/> /
    /// <see cref="Domain"/>). The active state retains it so a §3.6.5 re-poll re-composes the SAME
    /// request against the EXISTING binding — never re-minting a fresh challenge, which would desync the
    /// binding the holder is already answering. <see langword="null"/> only for a legacy active state
    /// restored before the query was retained, in which case a re-poll falls back to a §3.6 4xx.
    /// </summary>
    public string? PresentationQueryJson { get; init; }

    /// <summary>
    /// The §3.6.6 <c>variables.results</c> accumulated so far — per step name, the verbatim JSON of the
    /// result the engine recorded at a prior step (a verified <c>verifiablePresentation</c> or an issued
    /// credential's presentation). Empty until the first step records a result. A multi-step exchange
    /// carries the prior steps' results across the §3.6.5 advance so each step can reference them and the
    /// §3.6.6 view shows every step's output.
    /// </summary>
    public ImmutableDictionary<string, string> StepResults { get; init; } =
        ImmutableDictionary<string, string>.Empty;
}
