using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;

namespace Verifiable.Vcalm;

/// <summary>
/// Endpoint builder for the W3C VCALM 1.0 §3.7 "Initiating Interactions" coordinator surface
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) — the bootstrapping layer in front of the §3.6 exchanges. It exposes the §3.7.4
/// <c>GET /interactions/{localInteractionId}</c> interaction-protocols-response endpoint (the
/// content-negotiated <c>{protocols:{…}}</c> / <c>text/html</c> answer) and the §3.7.5
/// <c>POST /{localInviteId}/invite-request/response</c> inviteRequest endpoint. Register at startup via
/// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
/// </summary>
/// <remarks>
/// <para>
/// §2.1 / §3.7.1: the §3.7 interaction surface is hosted on a COORDINATOR (so its Web origin is a
/// consistent trust signal), distinct from the §3.2 / §3.3 / §3.5 / §3.6 SERVICE roles — it is gated by
/// the dedicated <see cref="WellKnownVcalmCapabilities.VcalmCoordinator"/> capability. Both endpoints
/// are stateless reads / records over the coordinator's interaction policy: the §3.7.4 protocols map is
/// resolved through <see cref="VcalmIntegration.ResolveVcalmInteractionProtocolsAsync"/>, and the
/// §3.7.6 vcapi entry in that map addresses a §3.6 exchange's §3.6.5 participate URL — this surface
/// POINTS AT the §3.6 exchange engine rather than re-implementing it.
/// </para>
/// <para>
/// §2.4 boundary MUSTs are enforced for the §3.7.5 body exactly as the other VCALM endpoints enforce
/// them; §3.8 RFC 9457 ProblemDetails answer a rejected inviteRequest (§3.7.5 400). The QR IMAGE is the
/// application's: the library EMITS / VALIDATES the §3.7.1 interaction URL (via
/// <see cref="VcalmInteractionUrlComposer"/>) and SERVES the §3.7.4 GET response that URL points at; it
/// does not render a QR code (§3.7.2 ISO-18004 encoding is a presentation concern, layered over the
/// validated URL).
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmInteractionEndpoints")]
public static class VcalmInteractionEndpoints
{
    //§3.7.5 path tail: the inviteRequest endpoint is POST /{localInviteId}/invite-request/response —
    //the inviteId is the segment before this fixed two-segment sub-resource.
    private const string InviteRequestSubPath = "invite-request/response";


    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        EndpointServer? server = context.Server;
        if(registration.AllowedCapabilities.Contains(WellKnownVcalmCapabilities.VcalmCoordinator))
        {
            VcalmIntegration? vcalm = server?.Vcalm();

            //§3.7.4 materializes only when the coordinator can resolve an interaction's protocols
            //(fail-closed — a §3.7.4 endpoint that cannot answer would be a dead route).
            if(vcalm?.ResolveVcalmInteractionProtocolsAsync is not null)
            {
                candidates.Add(BuildInteractionProtocols());
            }

            //§3.7.5 materializes only when the inviteRequest body parser is wired (fail-closed — the
            //endpoint cannot read its body without it; the store seam is OPTIONAL).
            if(vcalm?.ParseVcalmInviteRequestAsync is not null)
            {
                candidates.Add(BuildInviteRequest());
            }
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    //§3.7.4 GET /interactions/{localInteractionId}.
    private static EndpointCandidate BuildInteractionProtocols() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmInteractionProtocols,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownVcalmCapabilities.VcalmCoordinator,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            //§3.7.4: GET to the /interactions collection path plus a single {localInteractionId} segment.
            MatchesRequest = static (fields, context, endpoint, ct) =>
                MatchTrailingId(context, endpoint, WellKnownHttpMethods.Get),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                VcalmIntegration vcalm = server.Vcalm();

                string? interactionId = ExtractTrailingId(context);
                if(string.IsNullOrEmpty(interactionId))
                {
                    return (null, MalformedRequest());
                }

                //§3.7.4: an unknown interaction is a 404. The interaction existence is established by
                //the coordinator's protocols resolver.
                VcalmInteractionProtocols? protocols = await vcalm.ResolveVcalmInteractionProtocolsAsync!(
                    interactionId, context, ct).ConfigureAwait(false);
                if(protocols is null || !protocols.HasAnyProtocol)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                //§3.7.4 content negotiation: an Accept of application/json gets the {protocols:{…}}
                //JSON map MUST; any UNRECOGNIZED Accept gets the text/html human-directing document MUST.
                if(AcceptsJson(context))
                {
                    string jsonBody = VcalmInteractionResponseWriter.BuildProtocolsResponse(protocols);

                    return (null, ServerHttpResponse.Ok(jsonBody, WellKnownMediaTypes.Application.Json));
                }

                string htmlBody = VcalmInteractionResponseWriter.BuildHumanDirectionHtml();

                return (null, ServerHttpResponse.Ok(htmlBody, WellKnownMediaTypes.Text.Html));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.7.5 POST /{localInviteId}/invite-request/response.
    private static EndpointCandidate BuildInviteRequest() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmInviteRequest,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmCoordinator,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            //§3.7.5: POST to the /{localInviteId}/invite-request/response path — the inviteId is the
            //segment before the fixed "invite-request/response" sub-resource.
            MatchesRequest = static (fields, context, endpoint, ct) =>
                MatchInviteRequestPath(context, endpoint),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                VcalmIntegration vcalm = server.Vcalm();

                string? inviteId = ExtractInviteId(context);
                if(string.IsNullOrEmpty(inviteId))
                {
                    return (null, MalformedRequest());
                }

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    return (null, boundaryFailure);
                }

                VcalmInviteRequest? invite = await vcalm.ParseVcalmInviteRequestAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(invite is null || invite.Failure == VcalmParseFailure.Malformed)
                {
                    return (null, MalformedRequest());
                }

                if(invite.Failure == VcalmParseFailure.UnknownOption)
                {
                    return (null, UnknownOptionRequest());
                }

                //§3.7.5: record the accepted invitation under the inviteId when the coordinator wired a
                //store. The §3.7.5 body is accepted regardless (the store seam is OPTIONAL).
                if(vcalm.StoreVcalmInviteRequestAsync is { } store)
                {
                    await store(inviteId, invite, context, ct).ConfigureAwait(false);
                }

                //§3.7.5: a successful inviteRequest is a 200. The invitation conveys all of its
                //information in the request; the response carries no body of its own.
                return (null, ServerHttpResponse.Ok());
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§3.7.4 content negotiation: whether the request's Accept header asks for application/json. §3.7.4:
    //"When the interaction URL is fetched using an Accept header of application/json … When the
    //interaction URL is fetched using any unrecognized Accept header, a text/html document MUST be
    //returned." A request with no Accept, or an Accept that does not name application/json, takes the
    //text/html branch.
    private static bool AcceptsJson(ExchangeContext context)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null || !req.Headers.TryGetAll("Accept", out IReadOnlyList<string>? acceptValues) || acceptValues is null)
        {
            return false;
        }

        foreach(string acceptValue in acceptValues)
        {
            if(AcceptHeaderNamesJson(acceptValue))
            {
                return true;
            }
        }

        return false;
    }


    //Whether a single Accept header value names application/json among its comma-separated media
    //ranges, ignoring any q / parameter suffix on each range (RFC 9110 §12.5.1). The application/* and
    //*/* ranges are NOT treated as "recognized application/json": §3.7.4's contract is that ONLY an
    //application/json Accept gets the JSON body, everything else the text/html fallback.
    private static bool AcceptHeaderNamesJson(string acceptValue)
    {
        if(string.IsNullOrEmpty(acceptValue))
        {
            return false;
        }

        foreach(string range in acceptValue.Split(','))
        {
            int parameterSeparator = range.IndexOf(';', StringComparison.Ordinal);
            string mediaRange = (parameterSeparator >= 0 ? range[..parameterSeparator] : range).Trim();

            if(WellKnownMediaTypes.Application.IsJson(mediaRange))
            {
                return true;
            }
        }

        return false;
    }


    //Reads the {localInteractionId} path segment the §3.7.4 matcher extracted and carried on the match
    //payload, honouring a skin's RouteValues first.
    private static string? ExtractTrailingId(ExchangeContext context)
    {
        if(context.MatchPayload is VcalmInteractionIdMatchPayload payload && !string.IsNullOrEmpty(payload.Id))
        {
            return Uri.UnescapeDataString(payload.Id);
        }

        IncomingRequest? req = context.IncomingRequest;
        if(req is not null
            && req.RouteValues.TryGetValue(WellKnownVcalmRouteParameters.InteractionId, out string? routeValue)
            && !string.IsNullOrEmpty(routeValue))
        {
            return routeValue;
        }

        return null;
    }


    //Reads the {localInviteId} path segment the §3.7.5 matcher extracted and carried on the match
    //payload, honouring a skin's RouteValues first.
    private static string? ExtractInviteId(ExchangeContext context)
    {
        if(context.MatchPayload is VcalmInteractionIdMatchPayload payload && !string.IsNullOrEmpty(payload.Id))
        {
            return Uri.UnescapeDataString(payload.Id);
        }

        IncomingRequest? req = context.IncomingRequest;
        if(req is not null
            && req.RouteValues.TryGetValue(WellKnownVcalmRouteParameters.InviteId, out string? routeValue)
            && !string.IsNullOrEmpty(routeValue))
        {
            return routeValue;
        }

        return null;
    }


    //§3.7.4 matcher: the given method to the /interactions collection path plus a single non-empty
    //trailing {id} segment. Honours a skin's RouteValues id first.
    private static ValueTask<MatchPayload?> MatchTrailingId(
        ExchangeContext context, ServerEndpoint endpoint, string method)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null || !WellKnownHttpMethods.Equals(req.Method, method))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(req.RouteValues.TryGetValue(WellKnownVcalmRouteParameters.InteractionId, out string? routeValue)
            && !string.IsNullOrEmpty(routeValue))
        {
            return ValueTask.FromResult<MatchPayload?>(new VcalmInteractionIdMatchPayload(routeValue));
        }

        string collectionPath = endpoint.ResolvedUri.AbsolutePath;
        if(!TryExtractSingleTrailingSegment(req.Path, collectionPath, out string idSegment))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(new VcalmInteractionIdMatchPayload(idSegment));
    }


    //§3.7.5 matcher: POST to the resolved base path plus a single {localInviteId} segment followed by
    //the fixed "invite-request/response" sub-resource. Honours a skin's RouteValues inviteId first.
    private static ValueTask<MatchPayload?> MatchInviteRequestPath(ExchangeContext context, ServerEndpoint endpoint)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null || !WellKnownHttpMethods.Equals(req.Method, WellKnownHttpMethods.Post))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(req.RouteValues.TryGetValue(WellKnownVcalmRouteParameters.InviteId, out string? routeValue)
            && !string.IsNullOrEmpty(routeValue))
        {
            return ValueTask.FromResult<MatchPayload?>(new VcalmInteractionIdMatchPayload(routeValue));
        }

        string basePath = endpoint.ResolvedUri.AbsolutePath;
        if(!TryExtractInviteId(req.Path, basePath, out string idSegment))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(new VcalmInteractionIdMatchPayload(idSegment));
    }


    //Whether requestPath equals collectionPath + "/" + <single non-empty segment>. Strips query /
    //fragment, then checks the prefix and that exactly one non-empty trailing segment remains.
    private static bool TryExtractSingleTrailingSegment(string requestPath, string collectionPath, out string segment)
    {
        segment = string.Empty;

        ReadOnlySpan<char> tail = TrimPathToCollectionTail(requestPath, collectionPath);
        if(tail.Length == 0 || tail.Contains('/'))
        {
            return false;
        }

        segment = tail.ToString();

        return true;
    }


    //Whether requestPath equals basePath + "/" + {localInviteId} + "/invite-request/response", with
    //{localInviteId} a single non-empty segment. Strips query / fragment first.
    private static bool TryExtractInviteId(string requestPath, string basePath, out string inviteId)
    {
        inviteId = string.Empty;

        ReadOnlySpan<char> tail = TrimPathToCollectionTail(requestPath, basePath);
        if(tail.Length == 0)
        {
            return false;
        }

        ReadOnlySpan<char> suffix = InviteRequestSubPath.AsSpan();
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

        inviteId = idPart.ToString();

        return true;
    }


    //Strips a request path's query / fragment and the collection prefix, returning the trailing span
    //after "collectionPath/" (with a single trailing slash trimmed), or an empty span when the path does
    //not begin with the collection prefix followed by a slash.
    private static ReadOnlySpan<char> TrimPathToCollectionTail(string requestPath, string collectionPath)
    {
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
            return ReadOnlySpan<char>.Empty;
        }

        if(!pathSpan[..collectionSpan.Length].SequenceEqual(collectionSpan) || pathSpan[collectionSpan.Length] != '/')
        {
            return ReadOnlySpan<char>.Empty;
        }

        ReadOnlySpan<char> tail = pathSpan[(collectionSpan.Length + 1)..];
        if(tail.Length > 0 && tail[^1] == '/')
        {
            tail = tail[..^1];
        }

        return tail;
    }


    //§2.4 request-boundary MUSTs for the §3.7.5 body, mirroring the other VCALM endpoints: a body MUST
    //be present, within the configured size cap (else 413), and application/json (else 400).
    private static ServerHttpResponse? CheckRequestBoundary(
        ExchangeContext context, EndpointServer server, out string requestBody)
    {
        VcalmIntegration vcalm = server.Vcalm();
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


    //A §3.7.5 malformed-input 400 (an RFC 9457 ProblemDetail naming the malformed-value type).
    private static ServerHttpResponse MalformedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The request could not be parsed as a valid inviteRequest.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §2.4 unknown-option 400, carrying the §3.8 UNKNOWN_OPTION_PROVIDED type.
    private static ServerHttpResponse UnknownOptionRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.UnknownOptionProvided,
            "UNKNOWN_OPTION_PROVIDED",
            "A member unknown to the inviteRequest endpoint was provided to the API call.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }
}
