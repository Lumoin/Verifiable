using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.JCose;

using static Verifiable.Server.EndpointInput;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// Endpoint builder for the W3C VCALM 1.0 §3.6 workflows-and-exchanges engine
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) — the §3.6.3 <c>POST .../exchanges</c> create-exchange interface, the §1.3
/// conforming-holder REQUIRED §3.6.4 <c>GET .../exchanges/{id}/protocols</c> and §3.6.5
/// <c>POST .../exchanges/{id}</c> vcapi-participation interfaces, and the §3.6.6
/// <c>GET .../exchanges/{id}</c> exchange-state interface. Register at startup via
/// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
/// </summary>
/// <remarks>
/// <para>
/// The exchange instance is a pushdown automaton (<see cref="VcalmExchangeFlowKind"/>) on the neutral
/// Server PDA substrate — the structural mirror of the SIOPv2 / OID4VP verifier flows. The §3.6.3
/// create endpoint starts the flow (<see cref="VcalmExchangePendingState"/>); the §3.6.5 participate
/// endpoint loads the prior state and steps it on each vcapi message. The holder
/// <c>verifiablePresentation</c> verification is an EFFECT run in the participate endpoint's
/// <c>BuildInputAsync</c> (the §3.3.2 verify path) so the PDA transition stays pure — the same
/// effect-channeling the SIOP §11.1 validation uses. The §3.6.4 protocols and §3.6.6 state reads load
/// the persisted <c>FlowState</c> (the exchange-id → flow-id index the application keeps) and render
/// the §3.6.6 view from it through <see cref="VcalmStoredExchange.FromState"/> — there is no separate
/// exchange store to keep in sync with the flow state.
/// </para>
/// <para>
/// §2.4 boundary MUSTs are enforced on the §3.6.3 / §3.6.5 bodies exactly as the other VCALM
/// endpoints enforce them; §3.8 RFC 9457 ProblemDetails answer a rejected vcapi message (§3.6 4xx).
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmExchangeEndpoints")]
public static class VcalmExchangeEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        EndpointServer? server = context.Server;
        if(registration.AllowedCapabilities.Contains(WellKnownVcalmCapabilities.VcalmExchange))
        {
            var vcalm = server?.Vcalm();

            //The §3.6.4 / §3.6.6 reads need the exchange-id → flow-id resolver. The §3.6.3 create and
            //§3.6.5 participate additionally need their parsers and (for §3.6.5) the step-decision seam.
            //Fail-closed: an engine that cannot resolve, parse, or decide a step is a dead route.
            bool canResolve = vcalm?.ResolveVcalmExchangeFlowIdAsync is not null;

            if(canResolve && vcalm?.ParseVcalmCreateExchangeAsync is not null)
            {
                candidates.Add(BuildCreateExchange());
            }

            if(canResolve)
            {
                candidates.Add(BuildGetExchangeProtocols());
                candidates.Add(BuildGetExchangeState());
            }

            //§3.6.5: the participate endpoint needs the message parser and a step driver — either the
            //explicit step-decision seam (the single-step V-5b path) or the workflow resolver (the V-5c
            //config-driven step graph). One of the two suffices.
            if(canResolve
                && vcalm?.ParseVcalmExchangeMessageAsync is not null
                && (vcalm?.ResolveVcalmExchangeStepAsync is not null
                    || vcalm?.ResolveVcalmWorkflowForExchangeAsync is not null))
            {
                candidates.Add(BuildParticipateInExchange());
            }
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    //§3.6.3 POST /workflows/{localWorkflowId}/exchanges.
    private static EndpointCandidate BuildCreateExchange() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmCreateExchange,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmExchange,
            StartsNewFlow = true,
            Kind = VcalmExchangeFlowKind.Instance,

            //§3.6.3 is a POST to the /exchanges collection path exactly (no trailing id segment — that
            //is the §3.6.5 participate POST).
            MatchesRequest = static (fields, context, endpoint, ct) =>
                MatchExactCollection(context, endpoint, WellKnownHttpMethods.Post),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    return (null, boundaryFailure);
                }

                VcalmCreateExchangeRequest? request = await vcalm.ParseVcalmCreateExchangeAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null || request.Failure == VcalmParseFailure.Malformed)
                {
                    return (null, MalformedRequest());
                }

                if(request.Failure == VcalmParseFailure.UnknownOption)
                {
                    return (null, UnknownOptionRequest());
                }

                //§3.6.3: the exchange id is host-generic (like the §3.3.3 /challenges id), minted
                //through the dispatcher's identifier seam, NOT a VCALM-family seam.
                string exchangeId = await server.Integration.GenerateIdentifierAsync!(
                    WellKnownVcalmIdentifierPurposes.VcalmExchangeId, context, ct).ConfigureAwait(false);

                context.SetVcalmExchangeId(exchangeId);

                //§3.6.3: compose the exchange's vcapi participation URL (the §3.6.5 URL) for the
                //response Location header, through the deployment's endpoint-URI resolver.
                string? vcapiUrl = await ResolveProtocolUrlAsync(
                    server, WellKnownVcalmEndpointNames.VcalmParticipateInExchange, exchangeId, context, ct)
                    .ConfigureAwait(false);
                if(vcapiUrl is not null)
                {
                    context.SetVcalmExchangeVcapiUrl(vcapiUrl);
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                DateTimeOffset expiresAt = ResolveExpiresAt(request.Expires, now, vcalm);

                return Advance(new VcalmExchangeCreated
                {
                    FlowId = context.FlowId
                        ?? throw new InvalidOperationException(
                            "FlowId not on context. The dispatcher must place it before invoking "
                            + "BuildInputAsync on a StartsNewFlow endpoint."),
                    ExchangeId = exchangeId,
                    Expires = request.Expires,
                    VariablesJson = request.VariablesJson,
                    CreatedAt = now,
                    ExpiresAt = expiresAt
                });
            },

            //§3.6.3 201: the created exchange's §3.6.6-shaped state body (pending, sequence 0). The PDA
            //state is persisted by the dispatcher's SaveFlowStateAsync, which the application keys to
            //the minted exchange id (the §3.6.5 correlation index). The Location header carries the
            //exchange's vcapi URL when the deployment composed one.
            BuildResponse = static (state, _, context) =>
            {
                if(state is not VcalmExchangePendingState)
                {
                    return ServerHttpResponse.ServerError(
                        ServerErrors.ServerError,
                        $"Unexpected state after exchange creation: {state.GetType().Name}.");
                }

                VcalmStoredExchange? created = VcalmStoredExchange.FromState(state, stepCount: 0);
                if(created is null)
                {
                    return ServerHttpResponse.ServerError(
                        ServerErrors.ServerError, "The created exchange state could not be projected.");
                }

                string body = VcalmExchangeResponseWriter.BuildExchangeStateResponse(created);
                ServerHttpResponse response = ServerHttpResponse.Created(
                    body, WellKnownMediaTypes.Application.Json);

                string? location = context.VcalmExchangeVcapiUrl;

                return location is not null ? response.WithHeader("Location", location) : response;
            }
        };


    //§3.6.4 GET /workflows/{localWorkflowId}/exchanges/{localExchangeId}/protocols.
    private static EndpointCandidate BuildGetExchangeProtocols() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmGetExchangeProtocols,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownVcalmCapabilities.VcalmExchange,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            //§3.6.4: GET to the collection path + {id} + "/protocols" trailing segment.
            MatchesRequest = static (fields, context, endpoint, ct) =>
                MatchExchangeSubPath(context, endpoint, WellKnownHttpMethods.Get, "protocols"),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                string? exchangeId = ExtractExchangeId(context);
                if(string.IsNullOrEmpty(exchangeId))
                {
                    return (null, MalformedRequest());
                }

                //§3.6.4: an unknown exchange is a 404. The exchange existence is established by the
                //exchange-id → flow-id resolver.
                string? flowId = await vcalm.ResolveVcalmExchangeFlowIdAsync!(
                    exchangeId, context, ct).ConfigureAwait(false);
                if(flowId is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                //§3.6.4: the vcapi URL is REQUIRED (this engine always supports the vcapi protocol);
                //the optional OID4VP / OID4VCI / interact URLs are emitted only when the deployment's
                //ResolveEndpointUriAsync composed them. The vcapi URL is the §3.6.5 participation URL.
                string vcapiUrl = await ResolveProtocolUrlAsync(
                    server, WellKnownVcalmEndpointNames.VcalmParticipateInExchange, exchangeId, context, ct)
                    .ConfigureAwait(false)
                    ?? throw new InvalidOperationException(
                        "The deployment's ResolveEndpointUriAsync did not compose the vcapi participation "
                        + "URL for the exchange; §3.6.4 requires the vcapi protocol URL.");

                string body = VcalmExchangeResponseWriter.BuildProtocolsResponse(
                    vcapiUrl, openId4VpUrl: null, openId4VciUrl: null, interactUrl: null);

                return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.6.6 GET /workflows/{localWorkflowId}/exchanges/{localExchangeId}.
    private static EndpointCandidate BuildGetExchangeState() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmGetExchangeState,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownVcalmCapabilities.VcalmExchange,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            //§3.6.6: GET to the collection path + a single {id} trailing segment (no "/protocols").
            MatchesRequest = static (fields, context, endpoint, ct) =>
                MatchExchangeSubPath(context, endpoint, WellKnownHttpMethods.Get, subResource: null),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                string? exchangeId = ExtractExchangeId(context);
                if(string.IsNullOrEmpty(exchangeId))
                {
                    return (null, MalformedRequest());
                }

                //§3.6.6: an unknown exchange id is a 404.
                string? flowId = await vcalm.ResolveVcalmExchangeFlowIdAsync!(
                    exchangeId, context, ct).ConfigureAwait(false);
                if(flowId is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                //The §3.6.6 view is rendered from the persisted FlowState (loaded through the
                //host-generic flow-state seam) — the sequence is the step count, the state / step /
                //results / lastError read off the state record.
                (FlowState? state, int stepCount) = await server.Integration.LoadFlowStateAsync!(
                    context.TenantId!.Value, flowId, context, ct).ConfigureAwait(false);
                if(state is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                VcalmStoredExchange? view = VcalmStoredExchange.FromState(state, stepCount);
                if(view is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                string body = VcalmExchangeResponseWriter.BuildExchangeStateResponse(view);

                return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.6.5 POST /workflows/{localWorkflowId}/exchanges/{localExchangeId}.
    private static EndpointCandidate BuildParticipateInExchange() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmParticipateInExchange,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmExchange,
            StartsNewFlow = false,
            Kind = VcalmExchangeFlowKind.Instance,

            //§3.6.5: POST to the collection path + a single {id} trailing segment.
            MatchesRequest = static (fields, context, endpoint, ct) =>
                MatchExchangeSubPath(context, endpoint, WellKnownHttpMethods.Post, subResource: null),

            //The {localExchangeId} path segment is the correlation key the dispatcher resolves to the
            //internal flow id (the exchange-store secondary index), exactly as the SIOP state echo
            //resolves to the flow id.
            ExtractCorrelationKey = static (path, fields, context) => ExtractExchangeId(context),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    return (null, boundaryFailure);
                }

                //The exchange must be in a non-terminal state to accept a message. A complete / invalid
                //exchange answers the §3.6 4xx (a finished exchange cannot continue).
                if(currentState is VcalmExchangeCompleteState or VcalmExchangeInvalidState)
                {
                    return (null, ExchangeFinishedRequest());
                }

                VcalmExchangeMessage? message = await vcalm.ParseVcalmExchangeMessageAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(message is null || message.Failure == VcalmParseFailure.Malformed)
                {
                    //§3.6: an unrecognized custom property triggers an error.
                    return (null, MalformedRequest());
                }

                if(message.Failure == VcalmParseFailure.UnknownOption)
                {
                    return (null, UnknownOptionRequest());
                }

                string exchangeId = ExchangeIdOfState(currentState);

                return await ProcessVcapiMessageAsync(server, currentState, exchangeId, message, context, ct)
                    .ConfigureAwait(false);
            },

            //§3.6.5: write the vcapi reply the step staged on context. The advanced PDA state is
            //persisted by the dispatcher's SaveFlowStateAsync (the §3.6.6 sequence is the step count it
            //records), so the next §3.6.6 read renders the new state.
            BuildResponse = static (state, _, context) =>
                context.VcalmExchangeReply
                    ?? ServerHttpResponse.ServerError(
                        ServerErrors.ServerError, "The exchange step produced no vcapi reply.")
        };


    //§3.6.5 message processing: drive the engine's step decision (or verify a presented presentation),
    //stage the vcapi reply on context, and emit the PURE input that advances the PDA. The step driver is
    //the workflow's §3.6.1 step graph when one is resolved for the exchange (the V-5c config-driven
    //default), else the deployment's explicit step-decision seam (the single-step V-5b path).
    private static async ValueTask<(FlowInput? Input, ServerHttpResponse? Response)> ProcessVcapiMessageAsync(
        EndpointServer server,
        FlowState currentState,
        string exchangeId,
        VcalmExchangeMessage message,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var vcalm = server.Vcalm();
        DateTimeOffset now = server.TimeProvider.GetUtcNow();

        //Stamp the exchange id on context so the §3.6.7 callback body (composed during a step walk) can
        //carry the event.data.exchangeId.
        context.SetVcalmExchangeId(exchangeId);

        //§3.6.5 referenceId: the engine MAY include one; when present the holder SHOULD echo it. The
        //engine mints one per reply so debugging / message correlation works.
        string referenceId = await server.Integration.GenerateIdentifierAsync!(
            WellKnownVcalmIdentifierPurposes.VcalmExchangeReferenceId, context, cancellationToken)
            .ConfigureAwait(false);

        //§3.6.5 / §3.6.8: resolve the workflow the exchange runs on so the step decision DERIVES from
        //the §3.6.1 step graph (V-5c). When no workflow resolves, the engine falls back to the explicit
        //step-decision seam (the single-step V-5b path).
        VcalmWorkflowConfiguration? workflow = vcalm.ResolveVcalmWorkflowForExchangeAsync is { } resolveWorkflow
            ? await resolveWorkflow(exchangeId, context, cancellationToken).ConfigureAwait(false)
            : null;

        //When the holder presented a verifiablePresentation and the exchange is active (a request was
        //issued), VERIFY it against the bound challenge / domain — the effect kept out of the PDA. The
        //fail-closed property holds PER STEP: the challenge / domain are the CURRENT active step's, which
        //the engine bound when it requested this step's presentation; a presentation echoing a prior
        //step's challenge cannot verify against the current step's.
        if(message.VerifiablePresentation is DataIntegritySecuredPresentation presentation
            && currentState is VcalmExchangeActiveState active)
        {
            bool isVerified = await VcalmExchangeService.VerifyPresentationAsync(
                presentation,
                active.Challenge,
                active.Domain,
                vcalm.EffectiveExchangeVerification,
                context,
                cancellationToken).ConfigureAwait(false);

            if(!isVerified)
            {
                //§3.6 4xx: the presented presentation did not verify. Stage the ProblemDetails reply
                //and emit the rejection input that drives the exchange to invalid (keeping prior results).
                VcalmProblemDetail problem = VcalmProblemDetail.Error(
                    VcalmProblemTypes.CryptographicSecurityError,
                    "CRYPTOGRAPHIC_SECURITY_ERROR",
                    "The presented verifiablePresentation could not be verified against the exchange's "
                    + "bound challenge and domain.");

                context.SetVcalmExchangeReply(ProblemDetailsResponse(problem, 400));

                return Advance(new VcalmExchangeRejected
                {
                    StepName = active.StepName,
                    StepResults = active.StepResults,
                    ErrorType = problem.Type,
                    ErrorTitle = problem.Title!,
                    ErrorDetail = problem.Detail!,
                    FailedAt = now
                });
            }

            //§3.6.6: record the verified presentation under the step into variables.results.
            ImmutableDictionary<string, string> resultsAfterStep = active.StepResults.SetItem(
                active.StepName,
                BuildPresentationResult(message.VerifiablePresentationJson));

            //§3.6.5 / §3.6.8 multi-step: when the workflow's current step has a nextStep, the exchange
            //ADVANCES rather than completing — walk the step graph forward.
            if(workflow is not null
                && workflow.Steps.TryGetValue(active.StepName, out VcalmWorkflowStep? verifiedStep)
                && verifiedStep.NextStep is { } nextStep)
            {
                VcalmWorkflowAdvanceOutcome outcome = await VcalmWorkflowStepEngine.WalkAsync(
                    server, workflow, nextStep, resultsAfterStep, context, cancellationToken).ConfigureAwait(false);

                return await ApplyAdvanceOutcomeAsync(
                    server, vcalm, outcome, referenceId, advancingFromActive: true, context, cancellationToken)
                    .ConfigureAwait(false);
            }

            //The final step's presentation verified — complete the exchange (§3.6), carrying the full
            //accumulated results.
            context.SetVcalmExchangeReply(CompletionReply(referenceId));

            return Advance(new VcalmExchangePresentationVerified
            {
                StepName = active.StepName,
                VerifiablePresentationJson = message.VerifiablePresentationJson ?? string.Empty,
                StepResults = resultsAfterStep,
                VerifiedAt = now
            });
        }

        //A verifiablePresentation is honored only in the active state, where the engine has bound the
        //anti-replay challenge and domain it issued in its presentation request. A presentation that
        //arrives in any other state — before the engine has requested one — has no bound challenge to
        //verify against, so it is refused rather than allowed to drive the exchange forward unverified.
        //§3.6 binds a presentation to a prior request; a §3.6 verifier exchange never trusts an
        //unsolicited, unverifiable presentation. The exchange stays in its current state so the proper
        //request → present flow can still proceed.
        if(message.VerifiablePresentation is not null)
        {
            VcalmProblemDetail unsolicited = VcalmProblemDetail.Error(
                VcalmProblemTypes.CryptographicSecurityError,
                "CRYPTOGRAPHIC_SECURITY_ERROR",
                "A verifiablePresentation cannot be accepted before the exchange has requested one; "
                + "there is no bound anti-replay challenge to verify it against.");

            return (null, ProblemDetailsResponse(unsolicited, 400));
        }

        //The initiating / continuing non-presentation message. When the exchange is pending and a
        //workflow resolves, walk the step graph from its initialStep (V-5c); otherwise consult the
        //explicit step-decision seam (V-5b single-step).
        if(workflow is not null && currentState is VcalmExchangePendingState pending)
        {
            VcalmWorkflowAdvanceOutcome outcome = await VcalmWorkflowStepEngine.WalkAsync(
                server, workflow, workflow.InitialStep, pending.StepResults, context, cancellationToken)
                .ConfigureAwait(false);

            return await ApplyAdvanceOutcomeAsync(
                server, vcalm, outcome, referenceId, advancingFromActive: false, context, cancellationToken)
                .ConfigureAwait(false);
        }

        //§3.6.5: "Posting an empty body will start the exchange or return what the exchange is expecting
        //to complete the next step." On an exchange ALREADY active (the engine has issued a presentation
        //request and is awaiting it), a non-presentation re-poll RE-SENDS the current active step's
        //already-bound verifiablePresentationRequest with NO state change — recomposed from the query the
        //active state retained against the EXISTING active.Challenge / active.Domain, never re-minted, so
        //the fail-closed anti-replay binding the holder is answering survives the re-poll. This holds for
        //BOTH the workflow (V-5c) and single-step (V-5b) paths; the V-5b path formerly fell through to the
        //step seam below and re-minted a fresh challenge, desyncing the binding.
        if(currentState is VcalmExchangeActiveState repollActive)
        {
            return ResendActiveStepBoundRequest(repollActive, referenceId);
        }

        if(vcalm.ResolveVcalmExchangeStepAsync is not { } resolveStep)
        {
            //No workflow walk applied and no explicit step seam: nothing can decide the step.
            return (null, ServerHttpResponse.ServerError(
                ServerErrors.ServerError, "No exchange step logic is configured for this message."));
        }

        VcalmExchangeStepDecision decision = await resolveStep(
            exchangeId, message, context, cancellationToken).ConfigureAwait(false);

        return decision.Kind switch
        {
            VcalmExchangeStepKind.RequestPresentation =>
                await RequestPresentationAsync(
                    server, decision.StepName, decision.PresentationRequestQueryJson, domainOverride: decision.Domain,
                    referenceId, advancingFromActive: false, stepResults: ImmutableDictionary<string, string>.Empty,
                    context, cancellationToken).ConfigureAwait(false),

            VcalmExchangeStepKind.Redirect =>
                RedirectStep(
                    decision.RedirectUrl
                        ?? throw new InvalidOperationException("A Redirect step decision must carry the redirectUrl."),
                    referenceId, ImmutableDictionary<string, string>.Empty, context, now),

            //AcceptPresentation with no presentation in the message, or Complete: the engine has nothing
            //more to request nor offer.
            _ => CompleteStep(referenceId, ImmutableDictionary<string, string>.Empty, context, now)
        };
    }


    //Applies a §3.6.1 step-graph walk outcome: stages the vcapi reply, fires the suspending step's
    //callback (when one applies), and emits the PDA input that advances the exchange — a fresh-challenge
    //presentation request (from pending OR the multi-step active->active advance), a completion (empty /
    //with a server-offered presentation / redirect), or a rejection.
    private static async ValueTask<(FlowInput? Input, ServerHttpResponse? Response)> ApplyAdvanceOutcomeAsync(
        EndpointServer server,
        VcalmIntegration vcalm,
        VcalmWorkflowAdvanceOutcome outcome,
        string referenceId,
        bool advancingFromActive,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = server.TimeProvider.GetUtcNow();

        switch(outcome.Kind)
        {
            case VcalmWorkflowAdvanceKind.RequestPresentation:
            {
                (FlowInput? input, ServerHttpResponse? response) = await RequestPresentationAsync(
                    server, outcome.StepName, outcome.PresentationRequestQueryJson, domainOverride: null,
                    referenceId, advancingFromActive, outcome.StepResults, context, cancellationToken)
                    .ConfigureAwait(false);

                //§3.6.7: fire the step's callback after the request reply is staged.
                await FireCallbackAsync(vcalm, outcome.CallbackUrl, context, cancellationToken).ConfigureAwait(false);

                return (input, response);
            }

            case VcalmWorkflowAdvanceKind.CompleteWithPresentation:
            {
                context.SetVcalmExchangeReply(
                    ServerHttpResponse.Ok(
                        VcalmExchangeResponseWriter.BuildOfferedPresentationReply(
                            outcome.OfferedPresentationJson!, referenceId),
                        WellKnownMediaTypes.Application.Json));

                return Advance(new VcalmExchangeCompleted
                {
                    RedirectUrl = null,
                    StepResults = outcome.StepResults,
                    CompletedAt = now
                });
            }

            case VcalmWorkflowAdvanceKind.Redirect:
            {
                return RedirectStep(outcome.RedirectUrl!, referenceId, outcome.StepResults, context, now);
            }

            case VcalmWorkflowAdvanceKind.Invalid:
            {
                VcalmProblemDetail problem = VcalmProblemDetail.Error(
                    VcalmProblemTypes.MalformedValueError,
                    "MALFORMED_VALUE_ERROR",
                    outcome.FailureDetail ?? "The workflow step could not be executed.");

                context.SetVcalmExchangeReply(ProblemDetailsResponse(problem, 400));

                return Advance(new VcalmExchangeRejected
                {
                    StepName = outcome.StepName,
                    StepResults = outcome.StepResults,
                    ErrorType = problem.Type,
                    ErrorTitle = problem.Title!,
                    ErrorDetail = problem.Detail!,
                    FailedAt = now
                });
            }

            default:
            {
                context.SetVcalmExchangeReply(CompletionReply(referenceId));

                return Advance(new VcalmExchangeCompleted
                {
                    RedirectUrl = null,
                    StepResults = outcome.StepResults,
                    CompletedAt = now
                });
            }
        }
    }


    //§3.6.5 request-presentation step: mint and bind a FRESH anti-replay challenge, compose the §3.4
    //VPR, stage the verifiablePresentationRequest reply, and emit the request input. From pending the
    //input is VcalmExchangePresentationRequested (pending -> active); from active (a multi-step advance)
    //it is VcalmExchangeAdvancedToPresentation (active -> active), each binding its OWN fresh challenge.
    private static async ValueTask<(FlowInput? Input, ServerHttpResponse? Response)> RequestPresentationAsync(
        EndpointServer server,
        string stepName,
        string? queryJson,
        string? domainOverride,
        string referenceId,
        bool advancingFromActive,
        ImmutableDictionary<string, string> stepResults,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        DateTimeOffset now = server.TimeProvider.GetUtcNow();

        string challenge = await server.Integration.GenerateIdentifierAsync!(
            WellKnownVcalmIdentifierPurposes.VcalmExchangeChallenge, context, cancellationToken)
            .ConfigureAwait(false);

        //§3.4.1 domain: the deployment's value, else the participate URL host as the verifier target.
        string domain = domainOverride ?? ResolveDomainFallback(context);

        string query = queryJson
            ?? throw new InvalidOperationException(
                "A request-presentation step must carry the §3.4 query JSON to send.");

        string vprJson = VcalmExchangeService.BuildPresentationRequestJson(query, challenge, domain);

        context.SetVcalmExchangeReply(
            ServerHttpResponse.Ok(
                VcalmExchangeResponseWriter.BuildPresentationRequestReply(vprJson, referenceId),
                WellKnownMediaTypes.Application.Json));

        FlowInput input = advancingFromActive
            ? new VcalmExchangeAdvancedToPresentation
            {
                StepName = stepName,
                Challenge = challenge,
                Domain = domain,
                PresentationQueryJson = query,
                StepResults = stepResults,
                AdvancedAt = now
            }
            : new VcalmExchangePresentationRequested
            {
                StepName = stepName,
                Challenge = challenge,
                Domain = domain,
                PresentationQueryJson = query,
                StepResults = stepResults,
                RequestedAt = now
            };

        return Advance(input);
    }


    //§3.6.5 active re-poll: re-compose the current active step's verifiable presentation request from
    //the query the ACTIVE STATE retained and the EXISTING bound challenge / domain (active.Challenge /
    //active.Domain), and return it WITHOUT a PDA transition (a null FlowInput, so the dispatcher persists
    //no new state and re-binds no challenge). The holder that lost the first reply re-fetches the SAME
    //request it must still answer — re-minting a fresh challenge would desync the binding the holder is
    //already answering. Sourcing the query from the active state (not by re-resolving the step) makes the
    //resend identical for the workflow and single-step paths and never re-consults the step seam. When
    //the active state retained no query (a legacy restored state), a §3.6 4xx ProblemDetails is the
    //fallback — never a 500.
    private static (FlowInput? Input, ServerHttpResponse? Response) ResendActiveStepBoundRequest(
        VcalmExchangeActiveState active,
        string referenceId)
    {
        if(active.PresentationQueryJson is not { } queryJson)
        {
            VcalmProblemDetail problem = VcalmProblemDetail.Error(
                VcalmProblemTypes.MalformedValueError,
                "MALFORMED_VALUE_ERROR",
                "The active exchange step's verifiable presentation request could not be re-composed for a re-poll.");

            return (null, ProblemDetailsResponse(problem, 400));
        }

        string vprJson = VcalmExchangeService.BuildPresentationRequestJson(queryJson, active.Challenge, active.Domain);

        return (null, ServerHttpResponse.Ok(
            VcalmExchangeResponseWriter.BuildPresentationRequestReply(vprJson, referenceId),
            WellKnownMediaTypes.Application.Json));
    }


    private static (FlowInput? Input, ServerHttpResponse? Response) RedirectStep(
        string redirectUrl,
        string referenceId,
        ImmutableDictionary<string, string> stepResults,
        ExchangeContext context,
        DateTimeOffset now)
    {
        context.SetVcalmExchangeReply(
            ServerHttpResponse.Ok(
                VcalmExchangeResponseWriter.BuildRedirectReply(redirectUrl, referenceId),
                WellKnownMediaTypes.Application.Json));

        return Advance(new VcalmExchangeCompleted
        {
            RedirectUrl = redirectUrl,
            StepResults = stepResults,
            CompletedAt = now
        });
    }


    private static (FlowInput? Input, ServerHttpResponse? Response) CompleteStep(
        string referenceId,
        ImmutableDictionary<string, string> stepResults,
        ExchangeContext context,
        DateTimeOffset now)
    {
        context.SetVcalmExchangeReply(CompletionReply(referenceId));

        return Advance(new VcalmExchangeCompleted
        {
            RedirectUrl = null,
            StepResults = stepResults,
            CompletedAt = now
        });
    }


    //§3.6.7: fire the step's callback when it named one and the outbound-callback seam is wired. The
    //library composes the {event{data{exchangeId}}} body and invokes the delivery seam; the HTTP POST is
    //the application's (no System.Net.* in the library).
    private static async ValueTask FireCallbackAsync(
        VcalmIntegration vcalm, string? callbackUrl, ExchangeContext context, CancellationToken cancellationToken)
    {
        if(callbackUrl is not { } url || vcalm.DeliverVcalmCallbackAsync is not { } deliver)
        {
            return;
        }

        string body = VcalmCallbackComposer.ComposeCallbackBody(context.VcalmExchangeId ?? string.Empty);

        await deliver(url, body, context, cancellationToken).ConfigureAwait(false);
    }


    //§3.6.6 variables.results step value: { verifiablePresentation : <the verified presentation> }. The
    //presentation JSON rides through verbatim so the §3.6.6 view is byte-faithful.
    private static string BuildPresentationResult(string? presentationJson) =>
        VcalmExchangeResponseWriter.BuildStepPresentationResult(presentationJson ?? "{}");


    //§3.6.5: the empty completion reply carrying only the optional referenceId.
    private static ServerHttpResponse CompletionReply(string referenceId) =>
        ServerHttpResponse.Ok(
            VcalmExchangeResponseWriter.BuildCompletionReply(referenceId),
            WellKnownMediaTypes.Application.Json);


    //§3.6.3 expires resolution: the request's value when it parses, else the engine default lifetime
    //past now. The PDA expiry boundary; an expired exchange is rejected by the dispatcher's expiry gate.
    private static DateTimeOffset ResolveExpiresAt(string? expires, DateTimeOffset now, VcalmIntegration vcalm)
    {
        if(!string.IsNullOrEmpty(expires)
            && DateTimeOffset.TryParse(
                expires,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out DateTimeOffset parsed))
        {
            return parsed;
        }

        return now + vcalm.VcalmExchangeDefaultLifetime;
    }


    //The exchange id carried by the current non-terminal exchange state (the §3.6.5 participate path
    //always loads a pending / active state).
    private static string ExchangeIdOfState(FlowState state) => state switch
    {
        VcalmExchangePendingState pending => pending.ExchangeId,
        VcalmExchangeActiveState active => active.ExchangeId,
        _ => string.Empty
    };


    //Reads the {localExchangeId} path segment the matcher extracted and carried on the match payload,
    //honouring a skin's RouteValues first.
    private static string? ExtractExchangeId(ExchangeContext context)
    {
        if(context.MatchPayload is VcalmExchangeIdMatchPayload payload && !string.IsNullOrEmpty(payload.ExchangeId))
        {
            return Uri.UnescapeDataString(payload.ExchangeId);
        }

        IncomingRequest? req = context.IncomingRequest;
        if(req is not null
            && req.RouteValues.TryGetValue(WellKnownVcalmRouteParameters.ExchangeId, out string? routeValue)
            && !string.IsNullOrEmpty(routeValue))
        {
            return routeValue;
        }

        return null;
    }


    //§3.4.1 domain fallback: the issuer authority as the verifier target the holder binds to.
    private static string ResolveDomainFallback(ExchangeContext context) =>
        context.Issuer is { } issuer ? issuer.GetLeftPart(UriPartial.Authority) : "vcalm-exchange";


    //Composes a per-exchange protocol URL through the deployment's endpoint-URI resolver, stamping the
    //exchange id on context so the resolver can incorporate it.
    private static async ValueTask<string?> ResolveProtocolUrlAsync(
        EndpointServer server,
        string endpointName,
        string exchangeId,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(server.Integration.ResolveEndpointUriAsync is not { } resolve || context.Registration is not { } registration)
        {
            return null;
        }

        context.SetVcalmExchangeId(exchangeId);

        Uri? uri = await resolve(endpointName, registration, context, cancellationToken).ConfigureAwait(false);

        return uri?.OriginalString;
    }


    //Shared exact matcher: the given method to this endpoint's resolved /exchanges collection path
    //(no trailing id segment).
    private static ValueTask<MatchPayload?> MatchExactCollection(
        ExchangeContext context, ServerEndpoint endpoint, string method)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null || !WellKnownHttpMethods.Equals(req.Method, method))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
    }


    //§3.6.4 / §3.6.5 / §3.6.6 matcher: the given method to the /exchanges collection path plus a single
    //{id} segment, optionally followed by a fixed subResource segment ("protocols" for §3.6.4). When
    //subResource is null the path must be exactly collection/{id} (no further segments). Honours a
    //skin's RouteValues id first.
    private static ValueTask<MatchPayload?> MatchExchangeSubPath(
        ExchangeContext context, ServerEndpoint endpoint, string method, string? subResource)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null || !WellKnownHttpMethods.Equals(req.Method, method))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        string collectionPath = endpoint.ResolvedUri.AbsolutePath;
        if(!TryExtractExchangeTail(req.Path, collectionPath, subResource, out string idSegment))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(new VcalmExchangeIdMatchPayload(idSegment));
    }


    //Whether requestPath equals collectionPath + "/" + {id} (+ "/" + subResource when non-null), with
    //{id} a single non-empty segment. Strips query / fragment first.
    private static bool TryExtractExchangeTail(
        string requestPath, string collectionPath, string? subResource, out string idSegment)
    {
        idSegment = string.Empty;

        ReadOnlySpan<char> pathSpan = requestPath.AsSpan();
        int queryStart = pathSpan.IndexOf('?');
        if(queryStart >= 0) { pathSpan = pathSpan[..queryStart]; }

        int fragmentStart = pathSpan.IndexOf('#');
        if(fragmentStart >= 0) { pathSpan = pathSpan[..fragmentStart]; }

        ReadOnlySpan<char> collectionSpan = collectionPath.AsSpan();
        if(collectionSpan.Length > 1 && collectionSpan[^1] == '/')
        {
            collectionSpan = collectionSpan[..^1];
        }

        if(pathSpan.Length <= collectionSpan.Length + 1)
        {
            return false;
        }

        if(!pathSpan[..collectionSpan.Length].SequenceEqual(collectionSpan) || pathSpan[collectionSpan.Length] != '/')
        {
            return false;
        }

        ReadOnlySpan<char> tail = pathSpan[(collectionSpan.Length + 1)..];
        if(tail.Length > 0 && tail[^1] == '/')
        {
            tail = tail[..^1];
        }

        if(subResource is null)
        {
            //collection/{id} exactly — the tail is one non-empty segment with no slash.
            if(tail.Length == 0 || tail.Contains('/'))
            {
                return false;
            }

            idSegment = tail.ToString();

            return true;
        }

        //collection/{id}/{subResource} — the tail must end with "/{subResource}" and the prefix be a
        //single non-empty id segment.
        ReadOnlySpan<char> suffix = subResource.AsSpan();
        if(tail.Length <= suffix.Length + 1
            || !tail[^suffix.Length..].SequenceEqual(suffix)
            || tail[^(suffix.Length + 1)] != '/')
        {
            return false;
        }

        ReadOnlySpan<char> idPart = tail[..^(suffix.Length + 1)];
        if(idPart.Length == 0 || idPart.Contains('/'))
        {
            return false;
        }

        idSegment = idPart.ToString();

        return true;
    }


    //§2.4 request-boundary MUSTs for the §3.6.3 / §3.6.5 bodies, mirroring the other VCALM endpoints.
    private static ServerHttpResponse? CheckRequestBoundary(
        ExchangeContext context, EndpointServer server, out string requestBody)
    {
        var vcalm = server.Vcalm();
        requestBody = string.Empty;

        IncomingRequest? req = context.IncomingRequest;
        if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
        {
            return MalformedRequest();
        }

        if(req.Body.Bytes.Length > vcalm.VcalmMaxRequestBytes)
        {
            VcalmProblemDetail tooLarge = VcalmProblemDetail.Error(
                VcalmProblemTypes.MalformedValueError,
                "PAYLOAD_TOO_LARGE",
                "The request body exceeds the configured maximum payload size.");

            return ServerHttpResponse.PayloadTooLarge(
                VcalmResponseWriter.BuildProblemDetailBody(tooLarge), WellKnownMediaTypes.Application.Json);
        }

        if(!IsJsonContentType(req.Body.ContentType))
        {
            return MalformedRequest();
        }

        requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);

        return null;
    }


    private static bool IsJsonContentType(string contentType)
    {
        if(string.IsNullOrEmpty(contentType))
        {
            return false;
        }

        int separator = contentType.IndexOf(';', StringComparison.Ordinal);
        string mediaType = separator >= 0 ? contentType[..separator].Trim() : contentType.Trim();

        return WellKnownMediaTypes.Application.IsJson(mediaType);
    }


    //A §3.6.3 / §3.6.5 malformed-input 400 (an RFC 9457 ProblemDetail naming the malformed-value type).
    private static ServerHttpResponse MalformedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The request body could not be parsed as a valid exchange request or vcapi message.");

        return ProblemDetailsResponse(problem, 400);
    }


    //The §2.4 unknown-option 400, carrying the §3.8 UNKNOWN_OPTION_PROVIDED type.
    private static ServerHttpResponse UnknownOptionRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.UnknownOptionProvided,
            "UNKNOWN_OPTION_PROVIDED",
            "An option or property unknown to the exchange engine was provided to the API call.");

        return ProblemDetailsResponse(problem, 400);
    }


    //§3.6: a POST to a complete / invalid exchange — a finished exchange cannot continue. A §3.6 4xx.
    private static ServerHttpResponse ExchangeFinishedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The exchange has finished and cannot accept further vcapi messages.");

        return ProblemDetailsResponse(problem, 400);
    }


    private static ServerHttpResponse ProblemDetailsResponse(VcalmProblemDetail problem, int statusCode) =>
        ServerHttpResponse.Json(
            statusCode, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
}
