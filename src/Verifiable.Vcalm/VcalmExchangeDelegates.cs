using Verifiable.Core;

namespace Verifiable.Vcalm;

/// <summary>
/// Parses a VCALM 1.0 §3.6.3 <c>POST /workflows/{localWorkflowId}/exchanges</c> create-exchange
/// request body into the neutral <see cref="VcalmCreateExchangeRequest"/>. The default
/// <c>System.Text.Json</c> implementation lives in <c>Verifiable.Json</c> and is wired by the
/// application — the <c>Verifiable.Vcalm</c> serialization firewall keeps STJ out of the library.
/// </summary>
/// <remarks>
/// STRICT per §2.4: a body that is not a JSON object or carries a top-level member the engine does
/// not recognize is returned as the corresponding <see cref="VcalmParseFailure"/> rather than thrown.
/// The §3.6.3 body is all-optional, so the empty object is a valid request.
/// </remarks>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmCreateExchangeRequest?> ParseVcalmCreateExchangeDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a VCALM 1.0 §3.6.5 vcapi protocol message body into the neutral
/// <see cref="VcalmExchangeMessage"/>. The default <c>System.Text.Json</c> implementation lives in
/// <c>Verifiable.Json</c> and is wired by the application.
/// </summary>
/// <remarks>
/// STRICT per §2.4 / §3.6: a body that is not a JSON object, or carries a member the engine does not
/// recognize ("Custom properties and values might also be included, but are expected to trigger
/// errors in implementations that do not recognize them"), is returned as the corresponding
/// <see cref="VcalmParseFailure"/>. The empty object <c>{}</c> is the valid initiating message.
/// </remarks>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmExchangeMessage?> ParseVcalmExchangeMessageDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves a VCALM 1.0 §3.6 exchange's <c>{localExchangeId}</c> to the internal flow id its PDA
/// <c>FlowState</c> is persisted under, for the stateless §3.6.4 protocols and §3.6.6 state reads, or
/// <see langword="null"/> when no exchange exists for the id (the endpoints answer HTTP 404). Required
/// when the <see cref="WellKnownVcalmCapabilities.VcalmExchange"/> capability is allowed — without it
/// the engine cannot find an exchange's persisted state (fail-closed; the §3.6 routes do not
/// materialize). The application owns the exchange-id → flow-id index (the same secondary index the
/// §3.6.5 participation's correlation resolution uses); the §3.6 view is then rendered from the loaded
/// <c>FlowState</c>, so there is no separate exchange store to keep in sync.
/// </summary>
/// <param name="exchangeId">The local exchange id (the <c>{localExchangeId}</c> path segment).</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The internal flow id, or <see langword="null"/> when no exchange exists for the id.</returns>
public delegate ValueTask<string?> ResolveVcalmExchangeFlowIdDelegate(
    string exchangeId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Decides the engine's next §3.6.5 vcapi move for an exchange — the application's step logic. Given
/// the stored exchange and the client's incoming vcapi message, it returns a
/// <see cref="Exchange.VcalmExchangeStepDecision"/> naming one of the four §3.6 outcomes (request a
/// presentation, accept a presented one, complete, or redirect). Required when the
/// <see cref="WellKnownVcalmCapabilities.VcalmExchange"/> capability is allowed — the engine has no
/// built-in workflow, so without this seam there is no step logic (fail-closed; the §3.6 routes do
/// not materialize). This is the V-5c extension point: a workflow surface drives the same decisions
/// off an admin-authored step graph.
/// </summary>
/// <remarks>
/// The seam is the only application-owned policy in the exchange engine; everything else (challenge
/// minting, presentation verification, state-machine advance, persistence) the library does. For a
/// single-step present-or-offer exchange a deployment returns
/// <see cref="Exchange.VcalmExchangeStepDecision.RequestPresentation"/> on the empty initiating
/// message and <see cref="Exchange.VcalmExchangeStepDecision.AcceptPresentation"/> when the holder
/// presents.
/// </remarks>
/// <param name="exchangeId">The <c>{localExchangeId}</c> the message targets.</param>
/// <param name="message">The client's incoming vcapi message.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The engine's decision for this step.</returns>
public delegate ValueTask<Exchange.VcalmExchangeStepDecision> ResolveVcalmExchangeStepDelegate(
    string exchangeId,
    VcalmExchangeMessage message,
    ExchangeContext context,
    CancellationToken cancellationToken);
