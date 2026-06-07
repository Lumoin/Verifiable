using System.Text;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.JCose;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Routing;

namespace Verifiable.OAuth.Ssf;

/// <summary>
/// Endpoint builder for the OpenID Shared Signals Framework 1.0 Transmitter
/// surface — currently the <c>GET /.well-known/ssf-configuration</c> Transmitter
/// Configuration Metadata document (SSF §7), with the Stream Management API
/// endpoints joining it as the transmitter surface grows.
/// </summary>
/// <remarks>
/// <para>
/// Register at startup via <see cref="ServerConfiguration.EndpointBuilders"/>.
/// Emitted for registrations carrying
/// <see cref="WellKnownCapabilityIdentifiers.SsfTransmitter"/>.
/// </para>
/// <para>
/// <strong>Serialization firewall.</strong> The document is built by hand
/// through <see cref="JsonAppender"/>; the library derives <c>issuer</c> and the
/// endpoint URLs from the request's endpoint chain, while deployment policy
/// (delivery methods, critical subject members, authorization schemes, default
/// subjects) arrives through the
/// <see cref="AuthorizationServerIntegration.ContributeSsfTransmitterMetadataAsync"/>
/// seam.
/// </para>
/// </remarks>
public static class SsfTransmitterEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.SsfTransmitter))
        {
            candidates.Add(BuildSsfConfiguration());

            //Stream Management (§8.1.1) is active per operation only when its
            //store seam is wired — mirroring the AuthZEN optional-search
            //pattern: wired → active → advertised, fail-closed otherwise.
            AuthorizationServer? server = context.Server;
            if(server?.Integration.CreateSsfStreamAsync is not null
                && server.Integration.ParseSsfStreamCreateRequestAsync is not null)
            {
                candidates.Add(BuildStreamCreate());
            }

            if(server?.Integration.ReadSsfStreamsAsync is not null)
            {
                candidates.Add(BuildStreamRead());
            }

            if(server?.Integration.UpdateSsfStreamAsync is not null
                && server.Integration.ParseSsfStreamUpdateRequestAsync is not null)
            {
                candidates.Add(BuildStreamUpdate());
            }

            if(server?.Integration.ReplaceSsfStreamAsync is not null
                && server.Integration.ParseSsfStreamUpdateRequestAsync is not null)
            {
                candidates.Add(BuildStreamReplace());
            }

            if(server?.Integration.DeleteSsfStreamAsync is not null)
            {
                candidates.Add(BuildStreamDelete());
            }

            if(server?.Integration.ReadSsfStreamStatusAsync is not null)
            {
                candidates.Add(BuildStatusRead());
            }

            if(server?.Integration.UpdateSsfStreamStatusAsync is not null
                && server.Integration.ParseSsfStreamStatusAsync is not null)
            {
                candidates.Add(BuildStatusUpdate());
            }

            if(server?.Integration.AddSsfSubjectAsync is not null
                && server.Integration.ParseSsfAddSubjectRequestAsync is not null)
            {
                candidates.Add(BuildSubjectAdd());
            }

            if(server?.Integration.RemoveSsfSubjectAsync is not null
                && server.Integration.ParseSsfRemoveSubjectRequestAsync is not null)
            {
                candidates.Add(BuildSubjectRemove());
            }

            if(server?.Integration.TriggerSsfVerificationAsync is not null
                && server.Integration.ParseSsfVerificationRequestAsync is not null)
            {
                candidates.Add(BuildVerificationTrigger());
            }
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    private static EndpointCandidate BuildSsfConfiguration() =>
        new()
        {
            Name = WellKnownEndpointNames.SsfConfiguration,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.SsfTransmitter,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //DiscoveryMetadataKey null — the Transmitter Configuration Metadata is
            //itself a well-known document; it is not advertised inside the OAuth
            //discovery document.

            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }

                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;

                ClientRecord? registration = context.Registration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                EndpointChain? chain = context.EndpointChain;
                if(chain is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "EndpointChain not on context for SSF metadata emission. "
                        + "DispatchAsync sets this; this code path is only reachable "
                        + "through dispatch."));
                }

                //SSF §7.1: issuer is the Transmitter's Issuer Identifier and MUST
                //equal the iss claim of the SETs it emits. Resolve it through the
                //same seam the OAuth discovery document uses so a co-located
                //AS+Transmitter advertises one consistent identity.
                Uri issuer;
                try
                {
                    issuer = server.Integration.ResolveIssuerAsync is not null
                        ? await server.Integration.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false)
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Transmitter issuer identifier not found in context."));
                }

                SsfTransmitterMetadataContribution contribution =
                    server.Integration.ContributeSsfTransmitterMetadataAsync is null
                        ? SsfTransmitterMetadataContribution.Empty
                        : await server.Integration.ContributeSsfTransmitterMetadataAsync(
                            registration, context, ct).ConfigureAwait(false);

                string metadataJson = SsfTransmitterJsonWriting.BuildTransmitterConfigurationJson(
                    issuer, CollectEndpointMembers(chain), contribution);

                return (null, ServerHttpResponse.Ok(
                    metadataJson, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    //Reads the advertised endpoint members straight off the chain the dispatcher
    //built, so the document advertises exactly the endpoints active for this
    //request and the URL is the one the matcher binds to — no path composition,
    //no drift.
    private static List<KeyValuePair<string, string>> CollectEndpointMembers(EndpointChain chain)
    {
        List<KeyValuePair<string, string>> members = [];
        foreach(ServerEndpoint chainEndpoint in chain)
        {
            string? metadataField = MetadataFieldForEndpoint(chainEndpoint.Name);
            if(metadataField is null) { continue; }

            members.Add(new KeyValuePair<string, string>(metadataField, chainEndpoint.ResolvedUri.ToString()));
        }

        return members;
    }


    //Maps a chain endpoint role to the SSF §7.1 metadata member advertising it.
    //The five stream roles share one URL, so only the create role maps to
    //configuration_endpoint — advertising each would emit duplicate members.
    //Status, subject, and verification roles map here as they are built out.
    private static string? MetadataFieldForEndpoint(string endpointName)
    {
        if(endpointName == WellKnownEndpointNames.MetadataJwks)
        {
            return SsfMetadataParameterNames.JwksUri;
        }

        if(endpointName == WellKnownEndpointNames.SsfStreamCreate)
        {
            return SsfMetadataParameterNames.ConfigurationEndpoint;
        }

        if(endpointName == WellKnownEndpointNames.SsfStatusRead)
        {
            //Read and update share the Status Endpoint URL; only the read role
            //maps, avoiding a duplicate status_endpoint member.
            return SsfMetadataParameterNames.StatusEndpoint;
        }

        if(endpointName == WellKnownEndpointNames.SsfSubjectAdd)
        {
            return SsfMetadataParameterNames.AddSubjectEndpoint;
        }

        if(endpointName == WellKnownEndpointNames.SsfSubjectRemove)
        {
            return SsfMetadataParameterNames.RemoveSubjectEndpoint;
        }

        if(endpointName == WellKnownEndpointNames.SsfVerification)
        {
            return SsfMetadataParameterNames.VerificationEndpoint;
        }

        return null;
    }


    private static MatchPayload? MatchMethodAndPath(ExchangeContext context, ServerEndpoint endpoint, string method)
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null) { return null; }

        if(!WellKnownHttpMethods.Equals(req.Method, method)) { return null; }

        if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath)) { return null; }

        return MatchPayload.Empty;
    }


    private static EndpointCandidate BuildStreamCreate() =>
        new()
        {
            Name = WellKnownEndpointNames.SsfStreamCreate,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.SsfTransmitter,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                ValueTask.FromResult(MatchMethodAndPath(context, endpoint, WellKnownHttpMethods.Post)),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;
                ClientRecord registration = context.Registration!;
                IncomingRequest? req = context.IncomingRequest;

                ServerHttpResponse? denied = await AuthorizeAsync(
                    server, registration, context, WellKnownScopes.SsfManage, ct).ConfigureAwait(false);
                if(denied is not null)
                {
                    return (null, denied);
                }

                //§8.1.1.1: every Receiver-supplied member MAY be absent — an empty
                //body is a legal create that defaults to poll delivery.
                SsfStreamCreateRequest? request;
                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    request = new SsfStreamCreateRequest();
                }
                else
                {
                    string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);
                    request = await server.Integration.ParseSsfStreamCreateRequestAsync!(
                        requestBody, context, ct).ConfigureAwait(false);
                }

                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Create Stream request body cannot be parsed."));
                }

                SsfStreamWriteResult result = await server.Integration.CreateSsfStreamAsync!(
                    request, registration, context, ct).ConfigureAwait(false);

                return result.Outcome switch
                {
                    SsfStreamWriteOutcome.Success => (null, ServerHttpResponse.Created(
                        SsfTransmitterJsonWriting.BuildStreamConfigurationJson(result.Stream!), WellKnownMediaTypes.Application.Json)),
                    SsfStreamWriteOutcome.Conflict => (null, ServerHttpResponse.Conflict(
                        OAuthErrors.InvalidRequest, "The Transmitter does not support multiple streams per Receiver.")),
                    SsfStreamWriteOutcome.Forbidden => (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.UnauthorizedClient, "The Receiver is not allowed to create a stream.")),
                    _ => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Create Stream request is invalid."))
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static EndpointCandidate BuildStreamRead() =>
        new()
        {
            Name = WellKnownEndpointNames.SsfStreamRead,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.SsfTransmitter,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                ValueTask.FromResult(MatchMethodAndPath(context, endpoint, WellKnownHttpMethods.Get)),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;
                ClientRecord registration = context.Registration!;

                ServerHttpResponse? denied = await AuthorizeAsync(
                    server, registration, context, WellKnownScopes.SsfRead, ct).ConfigureAwait(false);
                if(denied is not null)
                {
                    return (null, denied);
                }

                //§8.1.1.2: stream_id query parameter selects one stream; absent
                //means "list every stream this Receiver has" (possibly empty).
                string? streamId = ReadStreamId(fields);

                IReadOnlyList<SsfStreamConfiguration>? streams = await server.Integration.ReadSsfStreamsAsync!(
                    streamId, registration, context, ct).ConfigureAwait(false);

                if(streams is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                string body = streamId is not null && streams.Count == 1
                    ? SsfTransmitterJsonWriting.BuildStreamConfigurationJson(streams[0])
                    : SsfTransmitterJsonWriting.BuildStreamConfigurationsJson(streams);

                return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json)
                    .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static EndpointCandidate BuildStreamUpdate() =>
        BuildStreamWrite(
            WellKnownEndpointNames.SsfStreamUpdate,
            WellKnownHttpMethods.Patch,
            static (server, request, registration, context, ct) =>
                server.Integration.UpdateSsfStreamAsync!(request, registration, context, ct));


    private static EndpointCandidate BuildStreamReplace() =>
        BuildStreamWrite(
            WellKnownEndpointNames.SsfStreamReplace,
            WellKnownHttpMethods.Put,
            static (server, request, registration, context, ct) =>
                server.Integration.ReplaceSsfStreamAsync!(request, registration, context, ct));


    //§8.1.1.3 (PATCH) and §8.1.1.4 (PUT) share the wire shape and status-code
    //mapping; only the store seam differs (merge versus replace semantics).
    private static EndpointCandidate BuildStreamWrite(
        string endpointName,
        string httpMethod,
        Func<AuthorizationServer, SsfStreamUpdateRequest, ClientRecord, ExchangeContext, CancellationToken, ValueTask<SsfStreamWriteResult>> store) =>
        new()
        {
            Name = endpointName,
            HttpMethod = httpMethod,
            Capability = WellKnownCapabilityIdentifiers.SsfTransmitter,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = (fields, context, endpoint, ct) =>
                ValueTask.FromResult(MatchMethodAndPath(context, endpoint, httpMethod)),

            BuildInputAsync = async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;
                ClientRecord registration = context.Registration!;
                IncomingRequest? req = context.IncomingRequest;

                ServerHttpResponse? denied = await AuthorizeAsync(
                    server, registration, context, WellKnownScopes.SsfManage, ct).ConfigureAwait(false);
                if(denied is not null)
                {
                    return (null, denied);
                }

                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The stream update request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);
                SsfStreamUpdateRequest? request = await server.Integration.ParseSsfStreamUpdateRequestAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The stream update request body cannot be parsed."));
                }

                SsfStreamWriteResult result = await store(server, request, registration, context, ct)
                    .ConfigureAwait(false);

                return result.Outcome switch
                {
                    SsfStreamWriteOutcome.Success => (null, ServerHttpResponse.Ok(
                            SsfTransmitterJsonWriting.BuildStreamConfigurationJson(result.Stream!), WellKnownMediaTypes.Application.Json)
                        .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore)),
                    SsfStreamWriteOutcome.Accepted => (null, ServerHttpResponse.Accepted()),
                    SsfStreamWriteOutcome.NotFound => (null, ServerHttpResponse.NotFound()),
                    SsfStreamWriteOutcome.Forbidden => (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.UnauthorizedClient, "The Receiver is not allowed to update the stream.")),
                    _ => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "A Transmitter-Supplied property is incorrect or the request is otherwise invalid."))
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static EndpointCandidate BuildStreamDelete() =>
        new()
        {
            Name = WellKnownEndpointNames.SsfStreamDelete,
            HttpMethod = WellKnownHttpMethods.Delete,
            Capability = WellKnownCapabilityIdentifiers.SsfTransmitter,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                ValueTask.FromResult(MatchMethodAndPath(context, endpoint, WellKnownHttpMethods.Delete)),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;
                ClientRecord registration = context.Registration!;

                ServerHttpResponse? denied = await AuthorizeAsync(
                    server, registration, context, WellKnownScopes.SsfManage, ct).ConfigureAwait(false);
                if(denied is not null)
                {
                    return (null, denied);
                }

                //§8.1.1.5: the stream_id query parameter is REQUIRED.
                string? streamId = ReadStreamId(fields);
                if(string.IsNullOrEmpty(streamId))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The stream_id query parameter is required."));
                }

                SsfStreamWriteOutcome outcome = await server.Integration.DeleteSsfStreamAsync!(
                    streamId, registration, context, ct).ConfigureAwait(false);

                return outcome switch
                {
                    SsfStreamWriteOutcome.Success => (null, ServerHttpResponse.NoContent()),
                    SsfStreamWriteOutcome.Forbidden => (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.UnauthorizedClient, "The Receiver is not allowed to delete the stream.")),
                    _ => (null, ServerHttpResponse.NotFound())
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static EndpointCandidate BuildStatusRead() =>
        new()
        {
            Name = WellKnownEndpointNames.SsfStatusRead,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.SsfTransmitter,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                ValueTask.FromResult(MatchMethodAndPath(context, endpoint, WellKnownHttpMethods.Get)),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;
                ClientRecord registration = context.Registration!;

                ServerHttpResponse? denied = await AuthorizeAsync(
                    server, registration, context, WellKnownScopes.SsfRead, ct).ConfigureAwait(false);
                if(denied is not null)
                {
                    return (null, denied);
                }

                //§8.1.2.1: the stream_id query parameter is REQUIRED.
                string? streamId = ReadStreamId(fields);
                if(string.IsNullOrEmpty(streamId))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The stream_id query parameter is required."));
                }

                SsfStreamStatus? status = await server.Integration.ReadSsfStreamStatusAsync!(
                    streamId, registration, context, ct).ConfigureAwait(false);
                if(status is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                return (null, ServerHttpResponse.Ok(
                        SsfTransmitterJsonWriting.BuildStreamStatusJson(status), WellKnownMediaTypes.Application.Json)
                    .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static EndpointCandidate BuildStatusUpdate() =>
        new()
        {
            Name = WellKnownEndpointNames.SsfStatusUpdate,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.SsfTransmitter,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                ValueTask.FromResult(MatchMethodAndPath(context, endpoint, WellKnownHttpMethods.Post)),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;
                ClientRecord registration = context.Registration!;
                IncomingRequest? req = context.IncomingRequest;

                ServerHttpResponse? denied = await AuthorizeAsync(
                    server, registration, context, WellKnownScopes.SsfManage, ct).ConfigureAwait(false);
                if(denied is not null)
                {
                    return (null, denied);
                }

                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The status update request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);
                SsfStreamStatus? requested = await server.Integration.ParseSsfStreamStatusAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(requested is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The status update request body cannot be parsed."));
                }

                SsfStreamStatusResult result = await server.Integration.UpdateSsfStreamStatusAsync!(
                    requested, registration, context, ct).ConfigureAwait(false);

                return result.Outcome switch
                {
                    SsfStreamOperationOutcome.Success => (null, ServerHttpResponse.Ok(
                            SsfTransmitterJsonWriting.BuildStreamStatusJson(result.Status!), WellKnownMediaTypes.Application.Json)
                        .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore)),
                    SsfStreamOperationOutcome.Accepted => (null, ServerHttpResponse.Accepted()),
                    SsfStreamOperationOutcome.NotFound => (null, ServerHttpResponse.NotFound()),
                    SsfStreamOperationOutcome.Forbidden => (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.UnauthorizedClient, "The Receiver is not allowed to update the stream status.")),
                    _ => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The status update request is invalid."))
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static EndpointCandidate BuildSubjectAdd() =>
        new()
        {
            Name = WellKnownEndpointNames.SsfSubjectAdd,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.SsfTransmitter,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                ValueTask.FromResult(MatchMethodAndPath(context, endpoint, WellKnownHttpMethods.Post)),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;
                ClientRecord registration = context.Registration!;
                IncomingRequest? req = context.IncomingRequest;

                ServerHttpResponse? denied = await AuthorizeAsync(
                    server, registration, context, WellKnownScopes.SsfManage, ct).ConfigureAwait(false);
                if(denied is not null)
                {
                    return (null, denied);
                }

                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Add Subject request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);
                SsfAddSubjectRequest? request = await server.Integration.ParseSsfAddSubjectRequestAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Add Subject request body cannot be parsed."));
                }

                SsfStreamOperationOutcome outcome = await server.Integration.AddSsfSubjectAsync!(
                    request, registration, context, ct).ConfigureAwait(false);

                return outcome switch
                {
                    //§8.1.3.2: an empty 200 — also the silent-accept privacy response.
                    SsfStreamOperationOutcome.Success => (null, ServerHttpResponse.Ok(
                        string.Empty, string.Empty)),
                    SsfStreamOperationOutcome.Forbidden => (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.UnauthorizedClient, "The Receiver is not allowed to add this subject.")),
                    SsfStreamOperationOutcome.TooManyRequests => (null, ServerHttpResponse.TooManyRequests(
                        OAuthErrors.InvalidRequest, "Too many subject requests; retry later.")),
                    _ => (null, ServerHttpResponse.NotFound())
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static EndpointCandidate BuildSubjectRemove() =>
        new()
        {
            Name = WellKnownEndpointNames.SsfSubjectRemove,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.SsfTransmitter,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                ValueTask.FromResult(MatchMethodAndPath(context, endpoint, WellKnownHttpMethods.Post)),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;
                ClientRecord registration = context.Registration!;
                IncomingRequest? req = context.IncomingRequest;

                ServerHttpResponse? denied = await AuthorizeAsync(
                    server, registration, context, WellKnownScopes.SsfManage, ct).ConfigureAwait(false);
                if(denied is not null)
                {
                    return (null, denied);
                }

                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Remove Subject request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);
                SsfRemoveSubjectRequest? request = await server.Integration.ParseSsfRemoveSubjectRequestAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Remove Subject request body cannot be parsed."));
                }

                SsfStreamOperationOutcome outcome = await server.Integration.RemoveSsfSubjectAsync!(
                    request, registration, context, ct).ConfigureAwait(false);

                return outcome switch
                {
                    //§8.1.3.3: an empty 204 — also the silent-accept privacy response.
                    SsfStreamOperationOutcome.Success => (null, ServerHttpResponse.NoContent()),
                    SsfStreamOperationOutcome.Forbidden => (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.UnauthorizedClient, "The Receiver is not allowed to remove this subject.")),
                    SsfStreamOperationOutcome.TooManyRequests => (null, ServerHttpResponse.TooManyRequests(
                        OAuthErrors.InvalidRequest, "Too many subject requests; retry later.")),
                    _ => (null, ServerHttpResponse.NotFound())
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static EndpointCandidate BuildVerificationTrigger() =>
        new()
        {
            Name = WellKnownEndpointNames.SsfVerification,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.SsfTransmitter,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
                ValueTask.FromResult(MatchMethodAndPath(context, endpoint, WellKnownHttpMethods.Post)),

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                AuthorizationServer server = context.Server!;
                ClientRecord registration = context.Registration!;
                IncomingRequest? req = context.IncomingRequest;

                ServerHttpResponse? denied = await AuthorizeAsync(
                    server, registration, context, WellKnownScopes.SsfManage, ct).ConfigureAwait(false);
                if(denied is not null)
                {
                    return (null, denied);
                }

                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The verification request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);
                SsfVerificationRequest? request = await server.Integration.ParseSsfVerificationRequestAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The verification request body cannot be parsed."));
                }

                SsfStreamOperationOutcome outcome = await server.Integration.TriggerSsfVerificationAsync!(
                    request, registration, context, ct).ConfigureAwait(false);

                return outcome switch
                {
                    //§8.1.4.2: 204 acknowledges the request only; the verification
                    //SET MAY be transmitted asynchronously.
                    SsfStreamOperationOutcome.Success => (null, ServerHttpResponse.NoContent()),
                    SsfStreamOperationOutcome.TooManyRequests => (null, ServerHttpResponse.TooManyRequests(
                        OAuthErrors.InvalidRequest,
                        "Verification requested more frequently than min_verification_interval permits.")),
                    _ => (null, ServerHttpResponse.NotFound())
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static string? ReadStreamId(RequestFields fields) =>
        fields.TryGetValue(SsfStreamConfigParameterNames.StreamId, out string? streamId)
            && !string.IsNullOrEmpty(streamId)
            ? streamId
            : null;


    //CAEP Interoperability Profile §2.7.3: when the authorization seam is wired,
    //every stream-management request must carry a token granting the operation's
    //scope (read APIs accept ssf.read, management APIs accept ssf.manage). The
    //token-validation composition is the application's, behind the seam; an
    //unset seam leaves the endpoints unauthenticated. The well-known discovery
    //document stays public per SSF §7.1.1.
    private static async ValueTask<ServerHttpResponse?> AuthorizeAsync(
        AuthorizationServer server,
        ClientRecord registration,
        ExchangeContext context,
        string requiredScope,
        CancellationToken cancellationToken)
    {
        if(server.Integration.AuthorizeSsfRequestAsync is null)
        {
            return null;
        }

        IncomingRequest? req = context.IncomingRequest;
        if(req is null)
        {
            return await UnauthorizedWithChallengeAsync(
                server, registration, context, cancellationToken).ConfigureAwait(false);
        }

        SsfRequestAuthorization outcome = await server.Integration.AuthorizeSsfRequestAsync(
            req, requiredScope, registration, context, cancellationToken).ConfigureAwait(false);

        return outcome switch
        {
            SsfRequestAuthorization.Authorized => null,
            SsfRequestAuthorization.Forbidden => ServerHttpResponse.Forbidden(
                OAuthErrors.InvalidScope, "The granted scope does not permit this operation."),
            _ => await UnauthorizedWithChallengeAsync(
                server, registration, context, cancellationToken).ConfigureAwait(false)
        };
    }


    /// <summary>
    /// Builds the <c>401</c> for a failed or missing authorization. The
    /// Transmitter is a protected resource (CAEP interop: Bearer in the
    /// Authorization header), so when its RFC 9728 metadata document is also
    /// served, the <c>WWW-Authenticate</c> challenge carries the
    /// <c>resource_metadata</c> URL (RFC 9728 §5.1) — the Receiver fetches it
    /// to discover the SSF scopes and authorization servers. The parameter is
    /// attached only when the metadata capability is active; advertising a
    /// URL that would 404 helps nobody.
    /// </summary>
    private static async ValueTask<ServerHttpResponse> UnauthorizedWithChallengeAsync(
        AuthorizationServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ServerHttpResponse response = ServerHttpResponse.Unauthorized(
            OAuthErrors.InvalidRequest, "Authorization failed or is missing.");

        if(!registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata))
        {
            return response;
        }

        //The same identity the metadata document derives its resource value
        //from, so the §3.3 validation holds by construction; the §3
        //path-insertion computation mirrors the consumer's.
        Uri issuer;
        try
        {
            issuer = server.Integration.ResolveIssuerAsync is not null
                ? await server.Integration.ResolveIssuerAsync(registration, context, cancellationToken)
                    .ConfigureAwait(false)
                : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken)
                    .ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            return response;
        }

        Uri metadataUrl = WellKnownPaths.OAuthProtectedResource.ComputeUri(issuer.OriginalString);

        return response.WithHeader(
            WellKnownHttpHeaderNames.WwwAuthenticate,
            ProtectedResourceChallenge.BuildChallenge(WellKnownAuthenticationSchemes.Bearer, metadataUrl));
    }
}
