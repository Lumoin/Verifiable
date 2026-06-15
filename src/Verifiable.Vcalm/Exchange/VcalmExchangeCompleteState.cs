using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// Terminal success of the W3C VCALM 1.0 §3.6 exchange: the engine has nothing more to request from
/// nor offer to the client, so the exchange is complete. The §3.6.6 state is <c>complete</c>.
/// </summary>
/// <remarks>
/// §3.6: "If that response object is empty, the exchange is complete and nothing is requested from
/// nor offered to the exchange client. […] If the object includes redirectUrl, the exchange is
/// complete and the workflow service recommends that the client proceed to another place." Both the
/// empty-reply completion and the redirectUrl completion land here. When the completion carried a
/// holder presentation that the engine verified during the final step, <see cref="ResultStepName"/> /
/// <see cref="VerifiablePresentationJson"/> carry it so the engine writes it into the §3.6.6
/// <c>variables.results</c>; <see cref="RedirectUrl"/> carries a §3.6 continue-elsewhere URL when the
/// completion was a redirect.
/// </remarks>
[DebuggerDisplay("VcalmExchangeCompleteState FlowId={FlowId} ExchangeId={ExchangeId}")]
public sealed record VcalmExchangeCompleteState: FlowState
{
    /// <summary>The §3.6 <c>{localExchangeId}</c> the exchange is addressed by.</summary>
    public required string ExchangeId { get; init; }

    /// <summary>The §3.6.3 <c>expires</c> the exchange was created with, verbatim, or <see langword="null"/> when unbounded.</summary>
    public string? Expires { get; init; }

    /// <summary>The verbatim §3.6.3 <c>variables</c> JSON the creator supplied, or <see langword="null"/> when none.</summary>
    public string? VariablesJson { get; init; }

    /// <summary>
    /// The §3.6.6 <c>step</c> the completing presentation was accepted at, or <see langword="null"/>
    /// when the exchange completed without a holder presentation (the empty-initiating-message
    /// completion).
    /// </summary>
    public string? ResultStepName { get; init; }

    /// <summary>
    /// The verbatim JSON of the holder <c>verifiablePresentation</c> the engine verified at the final
    /// step, or <see langword="null"/> when the exchange completed without one. Stored into the §3.6.6
    /// <c>variables.results</c> keyed by <see cref="ResultStepName"/>.
    /// </summary>
    public string? VerifiablePresentationJson { get; init; }

    /// <summary>
    /// The §3.6 <c>redirectUrl</c> the engine recommends the client continue at, or
    /// <see langword="null"/> when the exchange completed with an empty reply.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "§3.6 redirectUrl is a verbatim wire string the engine passes through opaquely; promoting to System.Uri would force parsing a value the protocol treats as opaque and would lose the caller's exact percent-encoding shape.")]
    public string? RedirectUrl { get; init; }

    /// <summary>
    /// The §3.6.6 <c>variables.results</c> accumulated across every step of the exchange — per step
    /// name, the verbatim JSON of the result the engine recorded (a verified
    /// <c>verifiablePresentation</c> or an issued credential's presentation). For a single-step
    /// present-or-offer exchange this carries the one verified presentation under
    /// <see cref="ResultStepName"/>; a multi-step exchange carries every step's output.
    /// </summary>
    public ImmutableDictionary<string, string> StepResults { get; init; } =
        ImmutableDictionary<string, string>.Empty;

    /// <summary>When the exchange completed.</summary>
    public required DateTimeOffset CompletedAt { get; init; }
}
