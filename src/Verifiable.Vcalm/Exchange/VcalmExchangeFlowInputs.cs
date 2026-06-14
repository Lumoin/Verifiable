using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Server;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// The create input that initiates the W3C VCALM 1.0 §3.6.3 exchange flow: the create-exchange
/// endpoint minted the <c>{localExchangeId}</c> and fixed the exchange's <c>expires</c>. Drives the
/// sentinel to <see cref="VcalmExchangePendingState"/>.
/// </summary>
public sealed record VcalmExchangeCreated: FlowInput
{
    /// <summary>The internal flow identifier.</summary>
    public required string FlowId { get; init; }

    /// <summary>The §3.6 <c>{localExchangeId}</c> minted for the new exchange.</summary>
    public required string ExchangeId { get; init; }

    /// <summary>The §3.6.3 <c>expires</c> the exchange is created with, verbatim, or <see langword="null"/> when unbounded.</summary>
    public string? Expires { get; init; }

    /// <summary>The verbatim §3.6.3 <c>variables</c> JSON the creator supplied, or <see langword="null"/> when none.</summary>
    public string? VariablesJson { get; init; }

    /// <summary>When the exchange was created.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>When the exchange expires (the PDA expiry boundary, derived from <see cref="Expires"/> or the engine default).</summary>
    public required DateTimeOffset ExpiresAt { get; init; }
}


/// <summary>
/// The §3.6.5 input the participate endpoint emits when the engine decides to request a presentation
/// from the holder — the engine answers the client's vcapi message with a §3.4 verifiable presentation
/// request bound to a fresh <see cref="Challenge"/> / <see cref="Domain"/>. Drives
/// <see cref="VcalmExchangePendingState"/> to <see cref="VcalmExchangeActiveState"/>.
/// </summary>
public sealed record VcalmExchangePresentationRequested: FlowInput
{
    /// <summary>The §3.6.6 <c>step</c> the issued request belongs to.</summary>
    public required string StepName { get; init; }

    /// <summary>The anti-replay <c>challenge</c> the engine bound the issued request to (§3.4.1).</summary>
    public required string Challenge { get; init; }

    /// <summary>The <c>domain</c> the engine bound the issued request to (§3.4.1).</summary>
    public required string Domain { get; init; }

    /// <summary>
    /// The §3.4 query JSON sent in the issued request, MINUS its <c>challenge</c> / <c>domain</c>,
    /// retained on the active state so a §3.6.5 re-poll re-composes the SAME request against the
    /// EXISTING binding rather than re-minting a fresh challenge.
    /// </summary>
    public required string PresentationQueryJson { get; init; }

    /// <summary>
    /// The §3.6.6 <c>variables.results</c> accumulated before this request — the prior steps' recorded
    /// results, carried forward so a multi-step exchange retains every step's output. Empty for the
    /// first request of an exchange.
    /// </summary>
    public ImmutableDictionary<string, string> StepResults { get; init; } =
        ImmutableDictionary<string, string>.Empty;

    /// <summary>When the request was issued.</summary>
    public required DateTimeOffset RequestedAt { get; init; }
}


/// <summary>
/// The §3.6.5 input the participate endpoint emits when a holder's presented <c>verifiablePresentation</c>
/// VERIFIED at the active step and the workflow's step graph has a NEXT step that itself requests a
/// presentation — the engine records the verified presentation under the completed step, advances the
/// step pointer, and issues a FRESH §3.4 verifiable presentation request bound to a fresh
/// <see cref="Challenge"/> / <see cref="Domain"/> for the next step. Drives
/// <see cref="VcalmExchangeActiveState"/> to a new <see cref="VcalmExchangeActiveState"/> (the
/// active → active multi-step advance V-5b lacked). The fresh challenge binding is what keeps the
/// fail-closed property per-step: each presentation-requesting step verifies only against its own
/// challenge, never a prior step's.
/// </summary>
public sealed record VcalmExchangeAdvancedToPresentation: FlowInput
{
    /// <summary>The §3.6.6 <c>step</c> the engine advanced to — the next step now requesting a presentation.</summary>
    public required string StepName { get; init; }

    /// <summary>The fresh anti-replay <c>challenge</c> the engine bound the next step's request to (§3.4.1).</summary>
    public required string Challenge { get; init; }

    /// <summary>The <c>domain</c> the engine bound the next step's request to (§3.4.1).</summary>
    public required string Domain { get; init; }

    /// <summary>
    /// The §3.4 query JSON sent in the next step's request, MINUS its <c>challenge</c> / <c>domain</c>,
    /// retained on the new active state so a §3.6.5 re-poll re-composes the SAME request against the
    /// EXISTING binding rather than re-minting a fresh challenge.
    /// </summary>
    public required string PresentationQueryJson { get; init; }

    /// <summary>
    /// The §3.6.6 <c>variables.results</c> accumulated through the just-completed step (it now includes
    /// the verified presentation the prior step recorded). Carried onto the new active state.
    /// </summary>
    public required ImmutableDictionary<string, string> StepResults { get; init; }

    /// <summary>When the next step's request was issued.</summary>
    public required DateTimeOffset AdvancedAt { get; init; }
}


/// <summary>
/// The §3.6.5 input the participate endpoint emits after it VERIFIED the holder's presented
/// <c>verifiablePresentation</c> against the active request's bound challenge / domain — the
/// verification is an EFFECT run in the endpoint's <c>BuildInputAsync</c> (the VCALM §3.3.2 verify
/// path), so this PURE input carries only the verdict and the verbatim presentation JSON. Drives
/// <see cref="VcalmExchangeActiveState"/> to terminal <see cref="VcalmExchangeCompleteState"/>.
/// </summary>
public sealed record VcalmExchangePresentationVerified: FlowInput
{
    /// <summary>The §3.6.6 <c>step</c> the verified presentation was accepted at (the final step of the exchange).</summary>
    public required string StepName { get; init; }

    /// <summary>The verbatim JSON of the verified holder <c>verifiablePresentation</c>, stored into <c>variables.results</c>.</summary>
    public required string VerifiablePresentationJson { get; init; }

    /// <summary>
    /// The §3.6.6 <c>variables.results</c> accumulated through this final step — the prior steps' results
    /// PLUS this step's verified presentation. The complete state carries this whole map so the §3.6.6
    /// view shows every step's output, not just the last.
    /// </summary>
    public required ImmutableDictionary<string, string> StepResults { get; init; }

    /// <summary>When verification completed.</summary>
    public required DateTimeOffset VerifiedAt { get; init; }
}


/// <summary>
/// The §3.6.5 input the participate endpoint emits when the engine completes the exchange with nothing
/// more to request nor offer — the client sent the empty initiating message and the engine has no
/// presentation to request (§3.6: an empty reply completes the exchange), or the engine completes with
/// a <c>redirectUrl</c> recommending the client continue elsewhere. Drives
/// <see cref="VcalmExchangePendingState"/> (or <see cref="VcalmExchangeActiveState"/>) to terminal
/// <see cref="VcalmExchangeCompleteState"/>.
/// </summary>
public sealed record VcalmExchangeCompleted: FlowInput
{
    /// <summary>The §3.6 <c>redirectUrl</c> the completion carried, or <see langword="null"/> for an empty-reply completion.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "§3.6 redirectUrl is a verbatim wire string the engine passes through opaquely; promoting to System.Uri would force parsing a value the protocol treats as opaque and would lose the caller's exact percent-encoding shape.")]
    public string? RedirectUrl { get; init; }

    /// <summary>
    /// The §3.6.6 <c>variables.results</c> accumulated by the time the exchange completed — the steps'
    /// recorded results (verified presentations, issued credentials' presentations). Empty for a bare
    /// empty-reply completion that recorded nothing; populated when a step issued a credential or the
    /// completing step recorded a result.
    /// </summary>
    public ImmutableDictionary<string, string> StepResults { get; init; } =
        ImmutableDictionary<string, string>.Empty;

    /// <summary>When the exchange completed.</summary>
    public required DateTimeOffset CompletedAt { get; init; }
}


/// <summary>
/// The §3.6.5 input the participate endpoint emits when a presented vcapi message is unacceptable —
/// the holder's <c>verifiablePresentation</c> failed verification against the bound challenge /
/// domain, or the message otherwise cannot advance the exchange. Drives any non-terminal exchange
/// state to terminal <see cref="VcalmExchangeInvalidState"/> (§3.6 4xx + ProblemDetails).
/// </summary>
public sealed record VcalmExchangeRejected: FlowInput
{
    /// <summary>The §3.6.6 <c>step</c> the failing message was presented at, or <see langword="null"/>.</summary>
    public string? StepName { get; init; }

    /// <summary>The §3.8 ProblemDetail type URL.</summary>
    public required string ErrorType { get; init; }

    /// <summary>The §3.8 ProblemDetail title.</summary>
    public required string ErrorTitle { get; init; }

    /// <summary>The §3.8 ProblemDetail detail.</summary>
    public required string ErrorDetail { get; init; }

    /// <summary>
    /// The §3.6.6 <c>variables.results</c> accumulated before the failure — the prior steps' recorded
    /// results, carried onto the invalid state so the §3.6.6 view still surfaces them. Empty when the
    /// failure occurred before any step recorded a result.
    /// </summary>
    public ImmutableDictionary<string, string> StepResults { get; init; } =
        ImmutableDictionary<string, string>.Empty;

    /// <summary>When the exchange failed.</summary>
    public required DateTimeOffset FailedAt { get; init; }
}
