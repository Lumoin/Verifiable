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
/// not materialize). An exchange for which <see cref="ResolveVcalmWorkflowForExchangeDelegate"/> resolves a
/// workflow is decided off that workflow's admin-authored step graph instead, the same kinds of decisions.
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


/// <summary>
/// The §3.6 operation a coordinator's request seeks: creating an exchange or reading its state.
/// <see cref="AuthorizeVcalmCoordinatorDelegate"/> is given one of these so the application's
/// authorization decision can differ by operation — <see href="https://www.w3.org/TR/vcalm-1.0/#workflows-and-exchanges">
/// VCALM 1.0 §3.6</see> "Initiating the exchange does not require any authorization beyond the
/// exchange URL" for <see cref="CreateExchange"/>, while "Querying the exchange in this way requires
/// additional authorization that the coordinator is expected to have and that the exchange client is
/// not" for <see cref="ReadExchangeState"/>.
/// </summary>
public enum VcalmCoordinatorOperation
{
    /// <summary>The §3.6.3 <c>POST /workflows/{localWorkflowId}/exchanges</c> create-exchange request.</summary>
    CreateExchange,

    /// <summary>The §3.6.6 <c>GET /workflows/{localWorkflowId}/exchanges/{localExchangeId}</c> state-read request.</summary>
    ReadExchangeState
}


/// <summary>
/// The neutral carrier <see cref="AuthorizeVcalmCoordinatorDelegate"/> is given to decide a §3.6
/// coordinator operation: which operation is sought, the exchange it targets, and the workflow's
/// declared §3.6.1 <c>authorization</c> configuration, when the exchange's workflow is known.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/vcalm-1.0/#workflows-and-exchanges">VCALM 1.0 §3.6</see>: workflow
/// authorization "to create and query particular workflow interactions … can be given to
/// coordinators." <see cref="ExchangeId"/> is <see langword="null"/> at creation — the §3.6.3 endpoint
/// mints the id only after this decision permits the request. <see cref="WorkflowAuthorization"/> is
/// likewise <see langword="null"/> at creation, because an exchange is not yet associated with a
/// workflow at that point in its lifecycle; a read carries the resolved exchange's workflow's
/// <see cref="VcalmWorkflowConfiguration.Authorization"/> when one resolves — and, per
/// <see cref="AuthorizeVcalmCoordinatorDelegate"/>'s remarks, when the workflow resolver itself resolves
/// no workflow for the id. The application reads the presented credential itself, off the per-request
/// <c>ExchangeContext.IncomingRequest</c> — this carrier states only WHAT is being decided.
/// </remarks>
public sealed record VcalmCoordinatorRequest
{
    /// <summary>The §3.6 operation this decision authorizes.</summary>
    public required VcalmCoordinatorOperation Operation { get; init; }

    /// <summary>
    /// The <c>{localExchangeId}</c> the request targets, or <see langword="null"/> for a
    /// <see cref="VcalmCoordinatorOperation.CreateExchange"/> request, which targets no existing
    /// exchange.
    /// </summary>
    public string? ExchangeId { get; init; }

    /// <summary>
    /// The targeted exchange's workflow's §3.6.1 <c>authorization</c> configuration, or
    /// <see langword="null"/> when none resolves — either because no workflow resolved for the
    /// exchange, the resolved workflow declares no <c>authorization</c>, or the operation is
    /// <see cref="VcalmCoordinatorOperation.CreateExchange"/> (an exchange does not know its workflow
    /// at creation). On a <see cref="VcalmCoordinatorOperation.ReadExchangeState"/> request this member
    /// is <see langword="null"/> for BOTH a known exchange with no declared authorization and an
    /// UNKNOWN exchange id — <see cref="AuthorizeVcalmCoordinatorDelegate"/> must decide the same way
    /// for both, never treating the absence as grounds to permit.
    /// </summary>
    public VcalmWorkflowAuthorization? WorkflowAuthorization { get; init; }
}


/// <summary>
/// An application's verdict on a §3.6 coordinator operation, returned from
/// <see cref="AuthorizeVcalmCoordinatorDelegate"/>. A denial carries the RFC 6750 §3
/// <c>WWW-Authenticate</c> challenge value the §3.6.3 / §3.6.6 endpoints answer HTTP 401 with.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/vcalm-1.0/#create-exchange">VCALM 1.0 §3.6.3</see> and
/// <see href="https://www.w3.org/TR/vcalm-1.0/#get-exchange-state">§3.6.6</see>: a coordinator
/// operation this instance refuses answers "401 Not Authorized". RFC 6750 §3: the response "MUST
/// include the HTTP 'WWW-Authenticate' response header field" — <see cref="Deny(string)"/> carries the
/// value that header is answered with. Construction is closed to <see cref="Permit"/> and
/// <see cref="Deny(string)"/> so a decision can never carry a permit with a challenge, or a denial
/// with none.
/// </remarks>
public sealed record VcalmCoordinatorDecision
{
    /// <summary>Whether the operation is permitted to proceed.</summary>
    public bool IsPermitted { get; private init; }

    /// <summary>
    /// The RFC 6750 §3 <c>WWW-Authenticate</c> challenge value a denial answers with, or
    /// <see langword="null"/> for <see cref="Permit"/>.
    /// </summary>
    public string? Challenge { get; private init; }


    /// <summary>Closes construction to this record's own <see cref="Permit"/> and <see cref="Deny(string)"/> factories.</summary>
    private VcalmCoordinatorDecision()
    {
    }


    /// <summary>The permitted verdict: the operation proceeds.</summary>
    public static VcalmCoordinatorDecision Permit { get; } = new() { IsPermitted = true };


    /// <summary>
    /// A denied verdict carrying the RFC 6750 §3 challenge the refusing 401 answers with as its
    /// <c>WWW-Authenticate</c> header value. The value carries only visible ASCII, space or horizontal
    /// tab — the <c>auth-param</c> grammar a <c>WWW-Authenticate</c> challenge is built from
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7235#section-2.1">RFC 7235 §2.1</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc7230#section-3.2">RFC 7230 §3.2</see>) never
    /// admits a carriage return, line feed or other control character into a header field value, and
    /// an application that echoed request-derived text into the challenge would otherwise be able to
    /// inject one.
    /// </summary>
    /// <param name="challenge">The <c>WWW-Authenticate</c> challenge value.</param>
    /// <returns>A non-permitted <see cref="VcalmCoordinatorDecision"/>.</returns>
    public static VcalmCoordinatorDecision Deny(string challenge)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(challenge);

        foreach(char character in challenge)
        {
            if(!IsValidChallengeCharacter(character))
            {
                throw new ArgumentException(
                    "A WWW-Authenticate challenge must contain only visible ASCII characters, space or horizontal tab.",
                    nameof(challenge));
            }
        }

        return new VcalmCoordinatorDecision { IsPermitted = false, Challenge = challenge };
    }


    /// <summary>
    /// Whether <paramref name="character"/> may appear in a <c>WWW-Authenticate</c> challenge: a
    /// visible ASCII character, space, or horizontal tab.
    /// </summary>
    /// <param name="character">The character to check.</param>
    /// <returns><see langword="true"/> when the character is admissible.</returns>
    private static bool IsValidChallengeCharacter(char character) => character switch
    {
        '\t' => true,
        _ when character is >= ' ' and <= '~' => true,
        _ => false
    };
}


/// <summary>
/// Authorizes a §3.6 coordinator's <see cref="VcalmCoordinatorRequest.Operation"/> against the
/// caller's own presented credential, read from <paramref name="context"/>. Required for the §3.6.3
/// create-exchange and §3.6.6 read-exchange-state routes to materialize, in the pattern
/// <see cref="VcalmIntegration.DeleteVcalmIssuedCredentialAsync"/> and
/// <see cref="VcalmIntegration.DeleteVcalmPresentationAsync"/> set for their own required seams: without
/// this seam wired, the engine cannot tell a coordinator's request from an anonymous one, so those two
/// routes do not materialize at all (HTTP 404) rather than serve unchecked (fail-closed).
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/vcalm-1.0/#workflows-and-exchanges">VCALM 1.0 §3.6</see>: workflow
/// authorization "to create and query particular workflow interactions … can be given to
/// coordinators"; <c>write:/exchanges</c> and <c>read:/exchanges</c> go "to a coordinator". A denial is
/// HTTP 401 with <see cref="VcalmCoordinatorDecision.Challenge"/> as the <c>WWW-Authenticate</c> header
/// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see>: the response "MUST
/// include the HTTP 'WWW-Authenticate' response header field") and an empty body, answered BEFORE the
/// §3.6.6 404 existence check on a read, so a denial never reveals whether the targeted exchange
/// exists.
/// </para>
/// <para>
/// The exchange resolved for a read is looked up, unauthenticated, before this delegate runs, so its
/// caller-chosen id reaches the workflow resolver before any credential is checked: the resolver MUST
/// answer <see langword="null"/>, never throw, for an id with no exchange, and this delegate MUST NOT
/// treat a <see langword="null"/> <see cref="VcalmCoordinatorRequest.WorkflowAuthorization"/> as
/// grounds to permit — an unknown exchange is denied exactly as a known one with a declared
/// authorization is, never on the strength of its own absence. The §3.6.4 protocols read is
/// unauthenticated by specification and answers 404 for an unknown id, so an exchange id's secrecy from
/// a caller who is not the coordinator rests on it being an unguessable capability URL
/// (<see cref="WellKnownVcalmIdentifierPurposes.VcalmExchangeId"/>), not on this seam.
/// </para>
/// </remarks>
/// <param name="request">What is being decided: the operation, the targeted exchange, and its workflow's declared authorization.</param>
/// <param name="context">The per-request context bag, carrying the inbound request the caller's credential is read from.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<VcalmCoordinatorDecision> AuthorizeVcalmCoordinatorDelegate(
    VcalmCoordinatorRequest request,
    ExchangeContext context,
    CancellationToken cancellationToken);
