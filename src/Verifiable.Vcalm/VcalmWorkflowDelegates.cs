using Verifiable.Core;
using Verifiable.JsonPointer.Jsonata;

namespace Verifiable.Vcalm;

/// <summary>
/// Parses a W3C VCALM 1.0 §3.6.1 <c>POST /workflows</c> create-workflow request body into the neutral
/// <see cref="VcalmWorkflowConfiguration"/>. The default <c>System.Text.Json</c> implementation lives
/// in <c>Verifiable.Json</c> and is wired by the application — the <c>Verifiable.Vcalm</c>
/// serialization firewall keeps STJ out of the library.
/// </summary>
/// <remarks>
/// STRICT per §2.4: a body that is not a JSON object, omits the REQUIRED <c>initialStep</c> /
/// <c>steps</c>, or carries a top-level member the engine does not recognize is returned as the
/// corresponding <see cref="VcalmParseFailure"/> rather than thrown. The §3.6.1 step-graph structural
/// MUSTs (initialStep / nextStep define defined steps; the final step carries no nextStep) are checked
/// separately by <see cref="VcalmWorkflowValidation"/> after a successful parse.
/// </remarks>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmWorkflowConfiguration?> ParseVcalmCreateWorkflowDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a W3C VCALM 1.0 §3.6.7 <c>POST /callbacks/{localCallbackId}</c> request body into the neutral
/// <see cref="VcalmCallbackRequest"/>. The default <c>System.Text.Json</c> implementation lives in
/// <c>Verifiable.Json</c>.
/// </summary>
/// <param name="requestBody">The request body, verbatim.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmCallbackRequest?> ParseVcalmCallbackDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Persists a W3C VCALM 1.0 §3.6.1 workflow configuration the <c>POST /workflows</c> endpoint accepted,
/// keyed by its <c>{localWorkflowId}</c>, so the §3.6.2 read and the §3.6.3 create-exchange endpoint can
/// reach it. The application owns the workflow store behind this seam. Required when the
/// <see cref="WellKnownVcalmCapabilities.VcalmAdministration"/> capability is allowed — without it the
/// §3.6.1 create endpoint cannot retain a workflow (fail-closed; the route does not materialize).
/// </summary>
/// <param name="workflowId">The minted (or caller-supplied) local workflow id.</param>
/// <param name="configuration">The validated workflow configuration to persist.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask StoreVcalmWorkflowDelegate(
    string workflowId,
    VcalmWorkflowConfiguration configuration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Loads a W3C VCALM 1.0 §3.6.1 workflow configuration by its <c>{localWorkflowId}</c> for the §3.6.2
/// <c>GET /workflows/{localWorkflowId}</c> read, or <see langword="null"/> when no workflow exists for
/// the id (the endpoint answers HTTP 404). Required when the
/// <see cref="WellKnownVcalmCapabilities.VcalmAdministration"/> capability is allowed.
/// </summary>
/// <param name="workflowId">The local workflow id (the <c>{localWorkflowId}</c> path segment).</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The stored workflow configuration, or <see langword="null"/> when none exists for the id.</returns>
public delegate ValueTask<VcalmWorkflowConfiguration?> LoadVcalmWorkflowDelegate(
    string workflowId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Resolves the W3C VCALM 1.0 §3.6.1 workflow configuration an exchange runs on, given the exchange's
/// <c>{localExchangeId}</c>, so the §3.6.5 exchange engine can DRIVE its step decisions off the
/// admin-authored step graph (the V-5c default for <see cref="ResolveVcalmExchangeStepDelegate"/>).
/// Returns <see langword="null"/> when the exchange has no workflow (a deployment that drives the step
/// decision through the explicit <see cref="ResolveVcalmExchangeStepDelegate"/> seam instead). The
/// application owns the exchange-id → workflow index (the exchange was created on a workflow at §3.6.3).
/// </summary>
/// <param name="exchangeId">The <c>{localExchangeId}</c> the step decision is being made for.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The workflow configuration the exchange runs on, or <see langword="null"/> when none.</returns>
public delegate ValueTask<VcalmWorkflowConfiguration?> ResolveVcalmWorkflowForExchangeDelegate(
    string exchangeId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Delivers a W3C VCALM 1.0 §3.6.7 step callback: POSTs the engine-composed <c>{event{data{exchangeId}}}</c>
/// body to the step's <c>callback.url</c> capability URL. The library carries NO <c>System.Net.*</c> —
/// the actual outbound HTTP POST is the application's, behind this seam; the library composes the body
/// and the target URL and invokes this delegate. Optional — when unwired, a step that names a callback
/// simply does not fire it (a deployment with no callback transport runs the exchange without callbacks).
/// </summary>
/// <param name="callbackUrl">The §3.6.1 <c>callback.url</c> capability URL to POST to.</param>
/// <param name="callbackBody">The verbatim <c>{event{data{exchangeId}}}</c> JSON body the engine composed.</param>
/// <param name="context">The per-request context bag, carrying the tenant identity.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask DeliverVcalmCallbackDelegate(
    string callbackUrl,
    string callbackBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a verbatim JSON fragment into the neutral <see cref="JsonataValue"/> model the §3.6 exchange
/// engine feeds to the credential-template evaluation — the exchange's <c>variables.results</c> (a
/// step's recorded presentation) and an issue request's per-request <c>variables</c>. The default
/// <c>System.Text.Json</c> implementation lives in <c>Verifiable.Json</c> and is wired by the
/// application — the <c>Verifiable.Vcalm</c> serialization firewall keeps STJ out of the library, so
/// the JSON → model adaptation crosses the boundary through this seam, exactly as the template
/// evaluation crosses through <see cref="VcalmTemplateEvaluatorRegistry"/>. Optional — when unwired, a
/// step's template is evaluated against an empty variable context (a constant credential body still
/// renders; a template that references a variable navigates it to nothing).
/// </summary>
/// <param name="json">The verbatim JSON fragment to adapt to the model.</param>
/// <returns>The adapted value, or <see cref="JsonataValue.Null"/> when the fragment is not parseable.</returns>
public delegate JsonataValue ParseVcalmTemplateInputDelegate(string json);
