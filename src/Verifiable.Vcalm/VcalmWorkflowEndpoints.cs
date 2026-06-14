using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;

using static Verifiable.Server.EndpointInput;

namespace Verifiable.Vcalm;

/// <summary>
/// Endpoint builder for the W3C VCALM 1.0 §3.6.1 / §3.6.2 administration surface and the §3.6.7
/// exchange-step-callback endpoint (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable
/// Credential API for Lifecycle Management</see>) — the §3.6.1 <c>POST /workflows</c> create-workflow
/// interface, the §3.6.2 <c>GET /workflows/{localWorkflowId}</c> get-workflow-configuration interface,
/// and the §3.6.7 <c>POST /callbacks/{localCallbackId}</c> callback interface. Register at startup via
/// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
/// </summary>
/// <remarks>
/// <para>
/// §3.1: the §3.6.1 / §3.6.2 endpoints' expected caller is "Administrators"; this engine gates them
/// behind the <see cref="WellKnownVcalmCapabilities.VcalmAdministration"/> capability (the deployment's
/// authorization mechanism is layered on top, as with every VCALM endpoint). The workflow CONFIG is the
/// admin-authored step graph the §3.6.3 create-exchange endpoint instantiates an exchange on; the
/// stored workflow is reached through the <see cref="VcalmIntegration"/> workflow seams.
/// </para>
/// <para>
/// §3.6.7: the callback endpoint receives the <c>{event{data{exchangeId}}}</c> body a workflow service
/// POSTs to a step's capability URL after the step executes, answering 200 / 400. The callback URL is a
/// capability URL (§3.6.7: ≥128-bit entropy when the <c>{localCallbackId}</c> form is used); possession
/// of the URL authorizes the POST, so no further authorization is required — the engine accepts the
/// body and acknowledges it. §2.4 boundary MUSTs and §3.8 ProblemDetails apply as throughout.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmWorkflowEndpoints")]
public static class VcalmWorkflowEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        EndpointServer? server = context.Server;
        if(registration.AllowedCapabilities.Contains(WellKnownVcalmCapabilities.VcalmAdministration))
        {
            var vcalm = server?.Vcalm();

            //§3.6.1 create needs the parser and the store seam; §3.6.2 read needs the load seam.
            //Fail-closed: a workflow service that cannot persist / load a workflow is a dead route.
            if(vcalm?.ParseVcalmCreateWorkflowAsync is not null && vcalm?.StoreVcalmWorkflowAsync is not null)
            {
                candidates.Add(BuildCreateWorkflow());
            }

            if(vcalm?.LoadVcalmWorkflowAsync is not null)
            {
                candidates.Add(BuildGetWorkflow());
            }

            //§3.6.7 callback: needs the body parser. The delivery side (firing a callback) is a separate
            //outbound seam; this is the RECEIVING side.
            if(vcalm?.ParseVcalmCallbackAsync is not null)
            {
                candidates.Add(BuildExchangeStepCallback());
            }
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    //§3.6.1 POST /workflows.
    private static EndpointCandidate BuildCreateWorkflow() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmCreateWorkflow,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmAdministration,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            //§3.6.1 is a POST to the /workflows collection path exactly (no trailing id segment).
            MatchesRequest = static (fields, context, endpoint, ct) =>
                VcalmPathMatching.MatchExactCollection(context, endpoint, WellKnownHttpMethods.Post),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    return (null, boundaryFailure);
                }

                VcalmWorkflowConfiguration? configuration = await vcalm.ParseVcalmCreateWorkflowAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(configuration is null || configuration.Failure == VcalmParseFailure.Malformed)
                {
                    return (null, MalformedRequest());
                }

                if(configuration.Failure == VcalmParseFailure.UnknownOption)
                {
                    return (null, UnknownOptionRequest());
                }

                //§3.6.1 step-graph structural MUSTs (initialStep / nextStep define defined steps; the
                //final step carries no nextStep; no cycle) → a 400 with the §3.8 ProblemDetail.
                VcalmProblemDetail? validation = VcalmWorkflowValidation.Validate(configuration);
                if(validation is not null)
                {
                    return (null, ProblemDetailsResponse(validation, 400));
                }

                //§3.6.1: the id is the caller's when supplied ("Passing an ID is OPTIONAL"), else minted
                //through the host-generic identifier seam.
                string workflowId = configuration.Id is { Length: > 0 } suppliedId
                    ? suppliedId
                    : await server.Integration.GenerateIdentifierAsync!(
                        WellKnownVcalmIdentifierPurposes.VcalmWorkflowId, context, ct).ConfigureAwait(false);

                VcalmWorkflowConfiguration stored = configuration with { Id = workflowId };
                await vcalm.StoreVcalmWorkflowAsync!(workflowId, stored, context, ct).ConfigureAwait(false);

                context.SetVcalmWorkflowId(workflowId);

                //§3.6.1: compose the workflow-metadata URL for the response Location header, through the
                //deployment's endpoint-URI resolver.
                string? location = await ResolveWorkflowUrlAsync(server, workflowId, context, ct).ConfigureAwait(false);
                if(location is not null)
                {
                    context.SetVcalmWorkflowLocation(location);
                }

                return (null, BuildCreatedResponse(workflowId, stored, context));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.6.2 GET /workflows/{localWorkflowId}.
    private static EndpointCandidate BuildGetWorkflow() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmGetWorkflow,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownVcalmCapabilities.VcalmAdministration,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            //§3.6.2: GET to the collection path + a single {id} trailing segment.
            MatchesRequest = static (fields, context, endpoint, ct) =>
                VcalmPathMatching.MatchCollectionItem(context, endpoint, WellKnownHttpMethods.Get),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                string? workflowId = VcalmPathMatching.ExtractItemId(context, WellKnownVcalmRouteParameters.WorkflowId);
                if(string.IsNullOrEmpty(workflowId))
                {
                    return (null, MalformedRequest());
                }

                //§3.6.2: an unknown workflow is a 404.
                VcalmWorkflowConfiguration? configuration = await vcalm.LoadVcalmWorkflowAsync!(
                    workflowId, context, ct).ConfigureAwait(false);
                if(configuration is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                string body = VcalmWorkflowResponseWriter.BuildWorkflowResponse(workflowId, configuration);

                return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.6.7 POST /callbacks/{localCallbackId}.
    private static EndpointCandidate BuildExchangeStepCallback() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmExchangeStepCallback,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmAdministration,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            //§3.6.7: POST to the /callbacks collection path + a single {id} (the capability-URL segment).
            MatchesRequest = static (fields, context, endpoint, ct) =>
                VcalmPathMatching.MatchCollectionItem(context, endpoint, WellKnownHttpMethods.Post),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                string? callbackId = VcalmPathMatching.ExtractItemId(context, WellKnownVcalmRouteParameters.CallbackId);
                if(string.IsNullOrEmpty(callbackId))
                {
                    return (null, MalformedRequest());
                }

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    //§3.6.7 400: "Callback data was not received."
                    return (null, boundaryFailure);
                }

                VcalmCallbackRequest? callback = await vcalm.ParseVcalmCallbackAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(callback is null
                    || callback.Failure != VcalmParseFailure.None
                    || string.IsNullOrEmpty(callback.ExchangeId))
                {
                    //§3.6.7 400: the body was not the {event{data{exchangeId}}} shape.
                    return (null, MalformedRequest());
                }

                //§3.6.7 200: "Callback data received." The capability URL's secret possession authorizes
                //the POST; the engine acknowledges the notification (a coordinator that wants the new
                //state then reads §3.6.6 at the carried exchangeId URL).
                return (null, ServerHttpResponse.Ok("{}", WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.6.1 201: the created workflow's configuration body, with the workflow-metadata Location header
    //when the deployment composed one. §3.6.1 also defines a 204 (without data); this engine returns the
    //stored config so a caller sees the resolved id and the normalized step graph.
    private static ServerHttpResponse BuildCreatedResponse(
        string workflowId, VcalmWorkflowConfiguration configuration, ExchangeContext context)
    {
        string body = VcalmWorkflowResponseWriter.BuildWorkflowResponse(workflowId, configuration);
        ServerHttpResponse response = ServerHttpResponse.Created(body, WellKnownMediaTypes.Application.Json);

        string? location = context.VcalmWorkflowLocation;

        return location is not null ? response.WithHeader("Location", location) : response;
    }


    //Composes the workflow-metadata URL through the deployment's endpoint-URI resolver, stamping the
    //workflow id on context so the resolver can incorporate it.
    private static async ValueTask<string?> ResolveWorkflowUrlAsync(
        EndpointServer server, string workflowId, ExchangeContext context, CancellationToken cancellationToken)
    {
        if(server.Integration.ResolveEndpointUriAsync is not { } resolve || context.Registration is not { } registration)
        {
            return null;
        }

        context.SetVcalmWorkflowId(workflowId);

        Uri? uri = await resolve(
            WellKnownVcalmEndpointNames.VcalmGetWorkflow, registration, context, cancellationToken).ConfigureAwait(false);

        return uri?.OriginalString;
    }


    //§2.4 request-boundary MUSTs for the §3.6.1 / §3.6.7 bodies, mirroring the other VCALM endpoints.
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


    private static ServerHttpResponse MalformedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The request body could not be parsed as a valid workflow configuration or callback notification.");

        return ProblemDetailsResponse(problem, 400);
    }


    private static ServerHttpResponse UnknownOptionRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.UnknownOptionProvided,
            "UNKNOWN_OPTION_PROVIDED",
            "An option or property unknown to the workflow service was provided to the API call.");

        return ProblemDetailsResponse(problem, 400);
    }


    private static ServerHttpResponse ProblemDetailsResponse(VcalmProblemDetail problem, int statusCode) =>
        ServerHttpResponse.Json(
            statusCode, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
}
