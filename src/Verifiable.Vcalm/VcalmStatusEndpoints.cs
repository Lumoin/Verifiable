using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.JCose;

namespace Verifiable.Vcalm;

/// <summary>
/// Endpoint builder for the W3C VCALM 1.0 status service
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) — the §C.3 <c>POST /credentials/status</c> interface a §1.3 conforming status
/// service MUST provide ("A conforming status service implementation MUST provide the interface
/// described in Section C.3 Update Status."), plus the MAY §C.1 <c>POST /status-lists</c> and §C.2
/// <c>GET /status-lists/{id}</c> interfaces. Register at startup via
/// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
/// </summary>
/// <remarks>
/// <para>
/// Appendix C labels itself non-normative, yet §1.3 makes §C.3 a MUST for a conforming status
/// service; §C.3 is therefore the binding conformance requirement here, and §C.1 / §C.2 are
/// supporting MAYs. The §C.3 endpoint dispatches to the application's status-update seam
/// (<see cref="VcalmIntegration.UpdateVcalmCredentialStatusAsync"/>): load the named status-list
/// credential, set / clear the bit, re-secure and persist. §C.1 composes
/// <see cref="VcalmStatusListService"/> over the V-2 issuance seam to build a NEW status-list
/// credential; §C.2 returns a stored one for verification.
/// </para>
/// <para>
/// §2.4 boundary MUSTs are enforced for the §C.3 / §C.1 bodies exactly as the issuer and verifier
/// enforce them: the body MUST be <c>application/json</c> (else 400), MUST be within
/// <see cref="VcalmIntegration.VcalmMaxRequestBytes"/> (else 413), and MUST NOT carry an option /
/// member the status service does not understand (an unknown option → 400 with the §3.8
/// <see cref="VcalmProblemTypes.UnknownOptionProvided"/> type). The §C privacy guidance prefers a
/// holder supplying the status list over a verifier phoning home; §C.2 is therefore public ("This
/// endpoint is typically publicly accessible without authentication").
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmStatusEndpoints")]
public static class VcalmStatusEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        EndpointServer? server = context.Server;
        if(registration.AllowedCapabilities.Contains(WellKnownVcalmCapabilities.VcalmStatus))
        {
            //§C.3 is the §1.3 binding status-service MUST; it materializes only when the parse seam
            //and the update seam are both wired (fail-closed — a status service that cannot read its
            //body or cannot mutate a status would be a dead route).
            if(server?.Vcalm().ParseVcalmUpdateStatusAsync is not null
                && server?.Vcalm().UpdateVcalmCredentialStatusAsync is not null)
            {
                candidates.Add(BuildUpdateStatus());
            }

            //§C.1 is a MAY; it needs the parse seam plus the status-list signing configuration — the
            //library never owns the signing key, so an instance with no §C.1 issuance does not
            //advertise list creation.
            if(server?.Vcalm().ParseVcalmCreateStatusListAsync is not null
                && (server?.Vcalm().VcalmStatusListIssuance is not null
                    || server?.Vcalm().ResolveVcalmStatusListIssuanceAsync is not null))
            {
                candidates.Add(BuildCreateStatusList());
            }

            //§C.2 is a MAY; it needs the matching load seam — the library never owns the status-list
            //store, so an instance with no store does not advertise retrieval.
            if(server?.Vcalm().LoadVcalmStatusListAsync is not null)
            {
                candidates.Add(BuildGetStatusList());
            }
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    //§C.3 POST /credentials/status — the §1.3 binding status-service MUST.
    private static EndpointCandidate BuildUpdateStatus() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmCredentialsStatus,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmStatus,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) => MatchPost(context, endpoint),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    return (null, boundaryFailure);
                }

                VcalmUpdateStatusRequest? request = await vcalm.ParseVcalmUpdateStatusAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null || request.Failure == VcalmParseFailure.Malformed)
                {
                    return (null, MalformedRequest());
                }

                //§2.4 unknown-option is checked before the entry-presence check: an unknown option
                //short-circuits the parser before it materializes the entry, and the §2.4 MUST is the
                //more specific outcome.
                if(request.Failure == VcalmParseFailure.UnknownOption)
                {
                    return (null, UnknownOptionRequest());
                }

                if(request.Entry is null || string.IsNullOrEmpty(request.CredentialId))
                {
                    return (null, MalformedRequest());
                }

                //§C.3: dispatch the single bit update to the application's storage boundary. The seam
                //loads the named status-list credential, sets / clears the bit, re-secures and
                //persists it, then reports the §C.3 200 / 404 verdict.
                VcalmStatusUpdateOutcome outcome = await vcalm.UpdateVcalmCredentialStatusAsync!(
                    request.CredentialId,
                    request.Entry,
                    request.Status,
                    request.IndexAllocator,
                    context,
                    ct).ConfigureAwait(false);

                //§C.3 responses: 200 "Credential status successfully updated", 404 "Credential not
                //found" (an unknown credential or an unknown status list).
                ServerHttpResponse response = outcome switch
                {
                    VcalmStatusUpdateOutcome.Updated => ServerHttpResponse.Ok(),
                    _ => ServerHttpResponse.NotFound()
                };

                return (null, response);
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§C.1 POST /status-lists (a MAY).
    private static EndpointCandidate BuildCreateStatusList() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmCreateStatusList,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownVcalmCapabilities.VcalmStatus,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) => MatchPost(context, endpoint),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                ServerHttpResponse? boundaryFailure = CheckRequestBoundary(context, server, out string requestBody);
                if(boundaryFailure is not null)
                {
                    return (null, boundaryFailure);
                }

                VcalmCreateStatusListRequest? request = await vcalm.ParseVcalmCreateStatusListAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null || request.Failure == VcalmParseFailure.Malformed)
                {
                    return (null, MalformedRequest());
                }

                if(request.Failure == VcalmParseFailure.UnknownOption)
                {
                    return (null, UnknownOptionRequest());
                }

                if(string.IsNullOrEmpty(request.StatusPurpose))
                {
                    return (null, MalformedRequest());
                }

                return (null, await CreateStatusListAsync(server, request, context, ct).ConfigureAwait(false));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§C.2 GET /status-lists/{id} (a MAY).
    private static EndpointCandidate BuildGetStatusList() =>
        new()
        {
            Name = WellKnownVcalmEndpointNames.VcalmGetStatusList,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownVcalmCapabilities.VcalmStatus,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                MatchStatusListIdPath(context, endpoint),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var vcalm = server.Vcalm();

                string? statusListId = ExtractStatusListId(context);
                if(string.IsNullOrEmpty(statusListId))
                {
                    return (null, MalformedRequest());
                }

                string? statusListJson = await vcalm.LoadVcalmStatusListAsync!(
                    statusListId, context, ct).ConfigureAwait(false);

                //§C.2: 404 "Status list not found" when no record exists, otherwise 200 with the
                //stored status-list credential. §C.2 is "typically publicly accessible without
                //authentication" (the §C privacy guidance prefers holders carrying the list over
                //verifiers phoning home).
                if(statusListJson is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                string body = VcalmResponseWriter.BuildVerifiableCredentialResponse(statusListJson);

                return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    //§C.1 creation: mint the status-list id when absent, compose and secure a new status-list
    //credential through the V-2 issuance seam, persist it under its id, and return the 201
    //{verifiableCredential, id} body.
    private static async ValueTask<ServerHttpResponse> CreateStatusListAsync(
        EndpointServer server,
        VcalmCreateStatusListRequest request,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var vcalm = server.Vcalm();

        //§C.1 status-list signing configuration, resolved for the request's tenant (the per-tenant
        //resolver or the flat server-global value). A multi-tenant host secures each tenant's status
        //lists under that tenant's own issuer identity and key.
        VcalmCredentialIssuance? issuance = await vcalm
            .ResolveEffectiveStatusListIssuanceAsync(context, cancellationToken).ConfigureAwait(false);
        if(issuance is null)
        {
            return ServerHttpResponse.ServerError(
                ServerErrors.ServerError, "No VCALM status-list issuance configuration resolved for this tenant.");
        }

        //§C.1 id: the caller-supplied id when present, else minted through the host-generic
        //identifier-generation seam ("If not provided, the service will generate one.") so a
        //deployment owns the value's format (e.g. the resolvable status-list-credential URL).
        string statusListId = !string.IsNullOrEmpty(request.Id)
            ? request.Id
            : await server.Integration.GenerateIdentifierAsync!(
                WellKnownVcalmIdentifierPurposes.VcalmStatusListId, context, cancellationToken).ConfigureAwait(false);

        DateTime proofCreated = server.TimeProvider.GetUtcNow().UtcDateTime;
        DataIntegritySecuredCredential securedStatusList = await VcalmStatusListService.CreateAsync(
            statusListId,
            request.StatusPurpose!,
            vcalm.VcalmStatusListEntryCount,
            issuance,
            proofCreated,
            context,
            cancellationToken).ConfigureAwait(false);

        string securedStatusListJson = issuance.SigningDescriptors[0].SerializeCredential(securedStatusList);

        //§C.2 persistence: store the secured list under its id so the retrieval interface and a later
        //§C.3 update can reach it. Optional — when unwired the list is still secured and returned.
        if(vcalm.StoreVcalmStatusListAsync is { } store)
        {
            await store(statusListId, securedStatusListJson, context, cancellationToken).ConfigureAwait(false);
        }

        string body = VcalmResponseWriter.BuildCreateStatusListResponse(securedStatusListJson, statusListId);

        return ServerHttpResponse.Created(body, WellKnownMediaTypes.Application.Json);
    }


    //Reads the {id} path segment the §C.2 matcher extracted and carried on the match payload. A skin
    //that did template routing (/status-lists/{statusListId}) populates the same id on the request's
    //RouteValues, which the matcher also honours.
    private static string? ExtractStatusListId(ExchangeContext context)
    {
        if(context.MatchPayload is VcalmStatusListIdMatchPayload payload && !string.IsNullOrEmpty(payload.StatusListId))
        {
            return Uri.UnescapeDataString(payload.StatusListId);
        }

        return null;
    }


    //Shared matcher: POST to this endpoint's resolved path.
    private static ValueTask<MatchPayload?> MatchPost(ExchangeContext context, ServerEndpoint endpoint)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null)
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(!WellKnownHttpMethods.IsPost(req.Method))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
    }


    //§C.2 path matcher: GET to a path that is the status service's resolved /status-lists collection
    //path plus a single non-empty trailing {id} segment. A skin that did template routing populates
    //the id on RouteValues; otherwise the request path must be {collection}/{id}.
    private static ValueTask<MatchPayload?> MatchStatusListIdPath(ExchangeContext context, ServerEndpoint endpoint)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null)
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(!WellKnownHttpMethods.Equals(req.Method, WellKnownHttpMethods.Get))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        if(req.RouteValues.TryGetValue(WellKnownVcalmRouteParameters.StatusListId, out string? routeValue)
            && !string.IsNullOrEmpty(routeValue))
        {
            return ValueTask.FromResult<MatchPayload?>(new VcalmStatusListIdMatchPayload(routeValue));
        }

        string collectionPath = endpoint.ResolvedUri.AbsolutePath;
        if(!TryExtractTrailingSegment(req.Path, collectionPath, out string idSegment))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(new VcalmStatusListIdMatchPayload(idSegment));
    }


    //Whether requestPath equals collectionPath + "/" + <single non-empty segment>. Strips the query
    //and fragment, then checks the prefix and that exactly one non-empty trailing segment remains.
    private static bool TryExtractTrailingSegment(string requestPath, string collectionPath, out string segment)
    {
        segment = string.Empty;

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

        //Strip a single trailing slash on the tail, then require exactly one non-empty segment.
        if(tail.Length > 0 && tail[^1] == '/')
        {
            tail = tail[..^1];
        }

        if(tail.Length == 0 || tail.Contains('/'))
        {
            return false;
        }

        segment = tail.ToString();

        return true;
    }


    //§2.4 request-boundary MUSTs for the §C.3 / §C.1 body, mirroring the issuer / verifier: a body
    //MUST be present, within the configured size cap (else 413), and application/json (else 400).
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


    //Compares the request content type to application/json case-insensitively, ignoring any media
    //type parameters (e.g. "; charset=utf-8") per RFC 9110 §8.3.1.
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


    //A §C.3 / §C.1 malformed-input 400 (an RFC 9457 ProblemDetail naming the malformed-value type).
    private static ServerHttpResponse MalformedRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.MalformedValueError,
            "MALFORMED_VALUE_ERROR",
            "The request body could not be parsed as a valid status request.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }


    //The §2.4 unknown-option 400, carrying the §3.8 UNKNOWN_OPTION_PROVIDED type.
    private static ServerHttpResponse UnknownOptionRequest()
    {
        VcalmProblemDetail problem = VcalmProblemDetail.Error(
            VcalmProblemTypes.UnknownOptionProvided,
            "UNKNOWN_OPTION_PROVIDED",
            "An option that is unknown to or unsupported by the status service instance was provided to the API call.");

        return ServerHttpResponse.Json(
            400, VcalmResponseWriter.BuildProblemDetailBody(problem), WellKnownMediaTypes.Application.Json);
    }
}
