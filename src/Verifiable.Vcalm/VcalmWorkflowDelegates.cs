using Verifiable.Core;

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
/// admin-authored step graph, which the engine prefers over <see cref="ResolveVcalmExchangeStepDelegate"/> whenever it
/// resolves one.
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
/// Locates the value of the top-level member of one UTF-8 JSON object whose name, with every escape decoded, is
/// <paramref name="memberName"/>, the reading a JSON parser gives the object:
/// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 §7</see>: "Any character may be escaped", so a
/// member name spelled with escapes is the member it spells. The §3.6 workflow engine decides through this seam
/// whether a template's rendered result wraps its credential under a <c>credential</c> member and whether an issue
/// request's variables redefine the reserved <c>results</c> member, never from the raw bytes of a member name. The
/// default implementation lives in <c>Verifiable.Json</c> and is wired by the application (serialization firewall).
/// </summary>
/// <remarks>
/// The answer is one of three (<see cref="VcalmJsonMemberLookup"/>). An object is read to its end before it is
/// answered for, so input that is not one well-formed JSON object, a top-level member name whose escapes spell no
/// Unicode string (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.2">RFC 8259 §8.2</see>: "The behavior of
/// software that receives JSON texts containing such values is unpredictable"), and a second top-level member of the
/// looked-up name (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 §4</see>: "When the names
/// within an object are not unique, the behavior of software that receives such an object is unpredictable") are
/// <see cref="VcalmJsonMemberLookup.Unreadable"/>, never read as carrying or lacking the member, so the engine never
/// decides one way while a later parser of the same text reads it another.
/// </remarks>
/// <param name="jsonObject">The UTF-8 JSON text of one object.</param>
/// <param name="memberName">The member name looked for, as the object's decoded member names are compared with it.</param>
/// <param name="valueRange">
/// The byte range of the member's value within <paramref name="jsonObject"/> when the answer is
/// <see cref="VcalmJsonMemberLookup.Found"/>, from the value's first byte to the byte after its last; the default range
/// otherwise.
/// </param>
/// <returns>Whether the object carries the member, lacks it, or cannot be read as one object whose members it could name.</returns>
public delegate VcalmJsonMemberLookup FindVcalmJsonMemberDelegate(ReadOnlySpan<byte> jsonObject, string memberName, out Range valueRange);


/// <summary>
/// The answer a <see cref="FindVcalmJsonMemberDelegate"/> gives about one top-level member of a UTF-8 JSON object: the
/// object carries it, the object lacks it, or the input cannot be read as one object whose top-level members it could
/// answer for. The third answer is its own value, so a caller refuses such input rather than reading it as either of
/// the other two.
/// </summary>
/// <remarks>
/// <see cref="Unreadable"/> is the default value, so an answer that was never set refuses.
/// </remarks>
public enum VcalmJsonMemberLookup
{
    /// <summary>
    /// The input is not one well-formed JSON object, a top-level member name spells no Unicode string, or two top-level
    /// members carry the looked-up name: nothing is decided about the member, and the caller refuses the input.
    /// </summary>
    Unreadable,

    /// <summary>The object, read to its end, carries no top-level member of the looked-up name.</summary>
    Absent,

    /// <summary>The object carries exactly one top-level member of the looked-up name, whose value the range locates.</summary>
    Found
}
