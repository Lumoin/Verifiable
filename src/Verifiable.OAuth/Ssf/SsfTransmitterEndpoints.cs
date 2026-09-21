using System.Text;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.JCose;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;

namespace Verifiable.OAuth.Ssf;

/// <summary>
/// Endpoint builder for the OpenID Shared Signals Framework 1.0 Transmitter
/// surface — currently the <c>GET /.well-known/ssf-configuration</c> Transmitter
/// Configuration Metadata document (SSF §7), with the Stream Management API
/// endpoints joining it as the transmitter surface grows.
/// </summary>
/// <remarks>
/// <para>
/// Register at startup via <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
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
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static EndpointBuilderDelegate Builder { get; } = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.SsfTransmitter))
        {
            candidates.Add(BuildSsfConfiguration());

            //SSF 1.0 §8-3: every Stream Management API endpoint MUST authorize the caller
            //against the Receiver's own streams. Unwired, there is no seam to ask, so no
            //Stream Management candidate is materialized — fail-closed, the same
            //materialize-only-when-wired rule the OAuth grant seams use
            //(AuthCodeEndpoints, client_credentials/token_exchange/jwt_bearer). The
            //well-known discovery document above stays public per SSF §7.1.1.
            EndpointServer? server = context.RequestServer;
            bool authorizationSeamWired = server?.OAuth().AuthorizeSsfRequestAsync is not null;

            //Stream Management (§8.1.1) is active per operation only when both the
            //authorization seam and its store seam are wired — mirroring the AuthZEN
            //optional-search pattern: wired → active → advertised, fail-closed otherwise.
            if(authorizationSeamWired
                && server?.OAuth().CreateSsfStreamAsync is not null
                && server?.OAuth().ParseSsfStreamCreateRequestAsync is not null)
            {
                candidates.Add(BuildStreamCreate());
            }

            if(authorizationSeamWired && server?.OAuth().ReadSsfStreamsAsync is not null)
            {
                candidates.Add(BuildStreamRead());
            }

            if(authorizationSeamWired
                && server?.OAuth().UpdateSsfStreamAsync is not null
                && server?.OAuth().ParseSsfStreamUpdateRequestAsync is not null)
            {
                candidates.Add(BuildStreamUpdate());
            }

            if(authorizationSeamWired
                && server?.OAuth().ReplaceSsfStreamAsync is not null
                && server?.OAuth().ParseSsfStreamUpdateRequestAsync is not null)
            {
                candidates.Add(BuildStreamReplace());
            }

            if(authorizationSeamWired && server?.OAuth().DeleteSsfStreamAsync is not null)
            {
                candidates.Add(BuildStreamDelete());
            }

            if(authorizationSeamWired && server?.OAuth().ReadSsfStreamStatusAsync is not null)
            {
                candidates.Add(BuildStatusRead());
            }

            if(authorizationSeamWired
                && server?.OAuth().UpdateSsfStreamStatusAsync is not null
                && server?.OAuth().ParseSsfStreamStatusAsync is not null)
            {
                candidates.Add(BuildStatusUpdate());
            }

            if(authorizationSeamWired
                && server?.OAuth().AddSsfSubjectAsync is not null
                && server?.OAuth().ParseSsfAddSubjectRequestAsync is not null)
            {
                candidates.Add(BuildSubjectAdd());
            }

            if(authorizationSeamWired
                && server?.OAuth().RemoveSsfSubjectAsync is not null
                && server?.OAuth().ParseSsfRemoveSubjectRequestAsync is not null)
            {
                candidates.Add(BuildSubjectRemove());
            }

            if(authorizationSeamWired
                && server?.OAuth().TriggerSsfVerificationAsync is not null
                && server?.OAuth().ParseSsfVerificationRequestAsync is not null)
            {
                candidates.Add(BuildVerificationTrigger());
            }
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    /// <summary>
    /// Builds the discovery endpoint from the admitted transmitter wiring and metadata contributions.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7">Shared Signals Framework §7</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
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
                    issuer = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false))!
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
                    oauth.ContributeSsfTransmitterMetadataAsync is null
                        ? SsfTransmitterMetadataContribution.Empty
                        : await oauth.ContributeSsfTransmitterMetadataAsync(
                            registration, context, ct).ConfigureAwait(false);

                //A contribution from which no profile-conformant document can be
                //built fails the request closed with the writer's diagnostic: a
                //Receiver that cannot discover the delivery methods is better off
                //seeing an error than a document that silently violates CAEP
                //Interoperability Profile §2.3.2.
                string metadataJson;
                try
                {
                    metadataJson = SsfTransmitterJsonWriting.BuildTransmitterConfigurationJson(
                        issuer, CollectEndpointMembers(chain), contribution);
                }
                catch(ArgumentException metadataRefusal)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, metadataRefusal.Message));
                }

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


    /// <summary>
    /// Builds the stream-creation endpoint using the admitted parser and creation store.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1">Shared Signals Framework §8.1.1.1</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();
                ClientRecord registration = context.ClientRegistration!;
                IncomingRequest? req = context.IncomingRequest;

                SsfAuthorizationOutcome authorization = await AuthorizeAsync(
                    server, registration, context, SsfRequestOperation.CreateStream,
                    WellKnownScopes.SsfManage, streamId: null, ct).ConfigureAwait(false);
                if(authorization.Denial is not null)
                {
                    return (null, authorization.Denial);
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
                    request = await oauth.ParseSsfStreamCreateRequestAsync!(
                        requestBody, context, ct).ConfigureAwait(false);
                }

                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Create Stream request body cannot be parsed."));
                }

                SsfStreamWriteResult result = await oauth.CreateSsfStreamAsync!(
                    request, registration, authorization.Receiver!, context, ct).ConfigureAwait(false);

                return result.Outcome switch
                {
                    SsfStreamWriteOutcome.Success => (null, ServerHttpResponse.Created(
                        SsfTransmitterJsonWriting.BuildStreamConfigurationJson(result.Stream!), WellKnownMediaTypes.Application.Json)),
                    SsfStreamWriteOutcome.Conflict => (null, ServerHttpResponse.Conflict(
                        OAuthErrors.InvalidRequest, "The Transmitter does not support multiple streams per Receiver.")),
                    SsfStreamWriteOutcome.Forbidden => (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.UnauthorizedClient, "The Receiver is not allowed to create a stream.")),

                    //Accepted, InvalidProperties, and NotFound are not outcomes a create can produce,
                    //but the delegate's declared return type still admits them, so they share the
                    //generic-invalid response rather than a 500 for an outcome no create rule uses.
                    SsfStreamWriteOutcome.Accepted => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Create Stream request is invalid.")),
                    SsfStreamWriteOutcome.InvalidProperties => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Create Stream request is invalid.")),
                    SsfStreamWriteOutcome.NotFound => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Create Stream request is invalid.")),

                    _ => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Create Stream request is invalid."))
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the stream-reading endpoint using the admitted stream store.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.2">Shared Signals Framework §8.1.1.2</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();
                ClientRecord registration = context.ClientRegistration!;

                //§8.1.1.2: stream_id query parameter selects one stream; absent
                //means "list every stream this Receiver has" (possibly empty). Read
                //before authorizing so the seam can answer 404 for a stream the caller
                //may not reach, per SSF 1.0 §8-3.
                string? streamId = ReadStreamId(fields);

                SsfAuthorizationOutcome authorization = await AuthorizeAsync(
                    server, registration, context, SsfRequestOperation.ReadStream,
                    WellKnownScopes.SsfRead, streamId, ct).ConfigureAwait(false);
                if(authorization.Denial is not null)
                {
                    return (null, authorization.Denial);
                }

                IReadOnlyList<SsfStreamConfiguration>? streams = await oauth.ReadSsfStreamsAsync!(
                    streamId, registration, authorization.Receiver!, context, ct).ConfigureAwait(false);

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
            SsfRequestOperation.UpdateStream,
            static (server, request, registration, receiver, context, ct) =>
                server.OAuth().UpdateSsfStreamAsync!(request, registration, receiver, context, ct));


    private static EndpointCandidate BuildStreamReplace() =>
        BuildStreamWrite(
            WellKnownEndpointNames.SsfStreamReplace,
            WellKnownHttpMethods.Put,
            SsfRequestOperation.ReplaceStream,
            static (server, request, registration, receiver, context, ct) =>
                server.OAuth().ReplaceSsfStreamAsync!(request, registration, receiver, context, ct));


    /// <summary>
    /// Builds a stream-write endpoint, selecting merge or replacement semantics for the requested method.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1">Shared Signals Framework §8.1.1</see>.
    /// </summary>
    private static EndpointCandidate BuildStreamWrite(
        string endpointName,
        string httpMethod,
        SsfRequestOperation operation,
        Func<EndpointServer, SsfStreamUpdateRequest, ClientRecord, SsfReceiver, ExchangeContext, CancellationToken, ValueTask<SsfStreamWriteResult>> store) =>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();
                ClientRecord registration = context.ClientRegistration!;
                IncomingRequest? req = context.IncomingRequest;

                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The stream update request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);
                SsfStreamUpdateRequest? request = await oauth.ParseSsfStreamUpdateRequestAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The stream update request body cannot be parsed."));
                }

                //§8.1.1.3/§8.1.1.4: the target stream_id rides the request body, so the body
                //is parsed before authorization runs — this happens before authorization and
                //reveals nothing about stream state either way, and it lets the decision
                //answer StreamNotAvailableToReceiver for this stream_id instead of only the
                //store's own not-found outcome.
                SsfAuthorizationOutcome authorization = await AuthorizeAsync(
                    server, registration, context, operation,
                    WellKnownScopes.SsfManage, request.StreamId, ct).ConfigureAwait(false);
                if(authorization.Denial is not null)
                {
                    return (null, authorization.Denial);
                }

                SsfStreamWriteResult result = await store(server, request, registration, authorization.Receiver!, context, ct)
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
                    SsfStreamWriteOutcome.InvalidProperties => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "A Transmitter-Supplied property is incorrect or the request is otherwise invalid.")),

                    //Conflict is not an outcome an update can produce, but the delegate's declared
                    //return type still admits it, so it shares the generic-invalid response rather
                    //than a 500 for an outcome no update rule uses.
                    SsfStreamWriteOutcome.Conflict => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "A Transmitter-Supplied property is incorrect or the request is otherwise invalid.")),

                    _ => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "A Transmitter-Supplied property is incorrect or the request is otherwise invalid."))
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the stream-deletion endpoint using the admitted deletion store.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.5">Shared Signals Framework §8.1.1.5</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();
                ClientRecord registration = context.ClientRegistration!;

                //§8.1.1.5: the stream_id query parameter is REQUIRED. Read before
                //authorizing so the seam can answer 404 for a stream the caller may not
                //reach, per SSF 1.0 §8-3.
                string? streamId = ReadStreamId(fields);

                SsfAuthorizationOutcome authorization = await AuthorizeAsync(
                    server, registration, context, SsfRequestOperation.DeleteStream,
                    WellKnownScopes.SsfManage, streamId, ct).ConfigureAwait(false);
                if(authorization.Denial is not null)
                {
                    return (null, authorization.Denial);
                }

                if(string.IsNullOrEmpty(streamId))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The stream_id query parameter is required."));
                }

                SsfStreamWriteOutcome outcome = await oauth.DeleteSsfStreamAsync!(
                    streamId, registration, authorization.Receiver!, context, ct).ConfigureAwait(false);

                return outcome switch
                {
                    SsfStreamWriteOutcome.Success => (null, ServerHttpResponse.NoContent()),
                    SsfStreamWriteOutcome.Forbidden => (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.UnauthorizedClient, "The Receiver is not allowed to delete the stream.")),
                    SsfStreamWriteOutcome.NotFound => (null, ServerHttpResponse.NotFound()),

                    //Accepted, InvalidProperties, and Conflict are not outcomes a delete can produce,
                    //but the delegate's declared return type still admits them, so they share
                    //NotFound's response rather than a 500 for an outcome no delete rule uses.
                    SsfStreamWriteOutcome.Accepted => (null, ServerHttpResponse.NotFound()),
                    SsfStreamWriteOutcome.InvalidProperties => (null, ServerHttpResponse.NotFound()),
                    SsfStreamWriteOutcome.Conflict => (null, ServerHttpResponse.NotFound()),

                    _ => (null, ServerHttpResponse.NotFound())
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the status-reading endpoint using the admitted status store.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2">Shared Signals Framework §8.1.2</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();
                ClientRecord registration = context.ClientRegistration!;

                //§8.1.2.1: the stream_id query parameter is REQUIRED. Read before
                //authorizing so the seam can answer 404 for a stream the caller may not
                //reach, per SSF 1.0 §8-3.
                string? streamId = ReadStreamId(fields);

                SsfAuthorizationOutcome authorization = await AuthorizeAsync(
                    server, registration, context, SsfRequestOperation.ReadStatus,
                    WellKnownScopes.SsfRead, streamId, ct).ConfigureAwait(false);
                if(authorization.Denial is not null)
                {
                    return (null, authorization.Denial);
                }

                if(string.IsNullOrEmpty(streamId))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The stream_id query parameter is required."));
                }

                SsfStreamStatus? status = await oauth.ReadSsfStreamStatusAsync!(
                    streamId, registration, authorization.Receiver!, context, ct).ConfigureAwait(false);
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


    /// <summary>
    /// Builds the status-update endpoint using the admitted parser and status store.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2">Shared Signals Framework §8.1.2</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();
                ClientRecord registration = context.ClientRegistration!;
                IncomingRequest? req = context.IncomingRequest;

                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The status update request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);
                SsfStreamStatus? requested = await oauth.ParseSsfStreamStatusAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(requested is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The status update request body cannot be parsed."));
                }

                //§8.1.2.2: the target stream_id rides the request body, so the body is
                //parsed before authorization runs — see the remark on BuildStreamWrite.
                SsfAuthorizationOutcome authorization = await AuthorizeAsync(
                    server, registration, context, SsfRequestOperation.UpdateStatus,
                    WellKnownScopes.SsfManage, requested.StreamId, ct).ConfigureAwait(false);
                if(authorization.Denial is not null)
                {
                    return (null, authorization.Denial);
                }

                SsfStreamStatusResult result = await oauth.UpdateSsfStreamStatusAsync!(
                    requested, registration, authorization.Receiver!, context, ct).ConfigureAwait(false);

                return result.Outcome switch
                {
                    SsfStreamOperationOutcome.Success => (null, ServerHttpResponse.Ok(
                            SsfTransmitterJsonWriting.BuildStreamStatusJson(result.Status!), WellKnownMediaTypes.Application.Json)
                        .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore)),
                    SsfStreamOperationOutcome.Accepted => (null, ServerHttpResponse.Accepted()),
                    SsfStreamOperationOutcome.NotFound => (null, ServerHttpResponse.NotFound()),
                    SsfStreamOperationOutcome.Forbidden => (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.UnauthorizedClient, "The Receiver is not allowed to update the stream status.")),
                    SsfStreamOperationOutcome.TooManyRequests => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The status update request is invalid.")),

                    _ => (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The status update request is invalid."))
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the subject-addition endpoint using the admitted parser and subject store.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3">Shared Signals Framework §8.1.3</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();
                ClientRecord registration = context.ClientRegistration!;
                IncomingRequest? req = context.IncomingRequest;

                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Add Subject request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);
                SsfAddSubjectRequest? request = await oauth.ParseSsfAddSubjectRequestAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Add Subject request body cannot be parsed."));
                }

                //§8.1.3.2: the target stream_id rides the request body, so the body is
                //parsed before authorization runs — see the remark on BuildStreamWrite.
                SsfAuthorizationOutcome authorization = await AuthorizeAsync(
                    server, registration, context, SsfRequestOperation.AddSubject,
                    WellKnownScopes.SsfManage, request.StreamId, ct).ConfigureAwait(false);
                if(authorization.Denial is not null)
                {
                    return (null, authorization.Denial);
                }

                SsfStreamOperationOutcome outcome = await oauth.AddSsfSubjectAsync!(
                    request, registration, authorization.Receiver!, context, ct).ConfigureAwait(false);

                return outcome switch
                {
                    //§8.1.3.2: an empty 200 — also the silent-accept privacy response.
                    SsfStreamOperationOutcome.Success => (null, ServerHttpResponse.Ok(
                        string.Empty, string.Empty)),
                    SsfStreamOperationOutcome.Forbidden => (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.UnauthorizedClient, "The Receiver is not allowed to add this subject.")),
                    SsfStreamOperationOutcome.TooManyRequests => (null, ServerHttpResponse.TooManyRequests(
                        OAuthErrors.InvalidRequest, "Too many subject requests; retry later.")),
                    SsfStreamOperationOutcome.NotFound => (null, ServerHttpResponse.NotFound()),

                    //Accepted is not an outcome an add can produce, but the delegate's declared
                    //return type still admits it, so it shares NotFound's response rather than a
                    //500 for an outcome no add rule uses.
                    SsfStreamOperationOutcome.Accepted => (null, ServerHttpResponse.NotFound()),

                    _ => (null, ServerHttpResponse.NotFound())
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the subject-removal endpoint using the admitted parser and subject store.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3">Shared Signals Framework §8.1.3</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();
                ClientRecord registration = context.ClientRegistration!;
                IncomingRequest? req = context.IncomingRequest;

                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Remove Subject request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);
                SsfRemoveSubjectRequest? request = await oauth.ParseSsfRemoveSubjectRequestAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The Remove Subject request body cannot be parsed."));
                }

                //§8.1.3.3: the target stream_id rides the request body, so the body is
                //parsed before authorization runs — see the remark on BuildStreamWrite.
                SsfAuthorizationOutcome authorization = await AuthorizeAsync(
                    server, registration, context, SsfRequestOperation.RemoveSubject,
                    WellKnownScopes.SsfManage, request.StreamId, ct).ConfigureAwait(false);
                if(authorization.Denial is not null)
                {
                    return (null, authorization.Denial);
                }

                SsfStreamOperationOutcome outcome = await oauth.RemoveSsfSubjectAsync!(
                    request, registration, authorization.Receiver!, context, ct).ConfigureAwait(false);

                return outcome switch
                {
                    //§8.1.3.3: an empty 204 — also the silent-accept privacy response.
                    SsfStreamOperationOutcome.Success => (null, ServerHttpResponse.NoContent()),
                    SsfStreamOperationOutcome.Forbidden => (null, ServerHttpResponse.Forbidden(
                        OAuthErrors.UnauthorizedClient, "The Receiver is not allowed to remove this subject.")),
                    SsfStreamOperationOutcome.TooManyRequests => (null, ServerHttpResponse.TooManyRequests(
                        OAuthErrors.InvalidRequest, "Too many subject requests; retry later.")),
                    SsfStreamOperationOutcome.NotFound => (null, ServerHttpResponse.NotFound()),

                    //Accepted is not an outcome a remove can produce, but the delegate's declared
                    //return type still admits it, so it shares NotFound's response rather than a
                    //500 for an outcome no remove rule uses.
                    SsfStreamOperationOutcome.Accepted => (null, ServerHttpResponse.NotFound()),

                    _ => (null, ServerHttpResponse.NotFound())
                };
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the verification endpoint using the admitted parser and verification trigger.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4">Shared Signals Framework §8.1.4</see>.
    /// </summary>
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();
                ClientRecord registration = context.ClientRegistration!;
                IncomingRequest? req = context.IncomingRequest;

                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The verification request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);
                SsfVerificationRequest? request = await oauth.ParseSsfVerificationRequestAsync!(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "The verification request body cannot be parsed."));
                }

                //§8.1.4.2: the target stream_id rides the request body, so the body is
                //parsed before authorization runs — see the remark on BuildStreamWrite.
                SsfAuthorizationOutcome authorization = await AuthorizeAsync(
                    server, registration, context, SsfRequestOperation.Verify,
                    WellKnownScopes.SsfManage, request.StreamId, ct).ConfigureAwait(false);
                if(authorization.Denial is not null)
                {
                    return (null, authorization.Denial);
                }

                SsfStreamOperationOutcome outcome = await oauth.TriggerSsfVerificationAsync!(
                    request, registration, authorization.Receiver!, context, ct).ConfigureAwait(false);

                return outcome switch
                {
                    //§8.1.4.2: 204 acknowledges the request only; the verification
                    //SET MAY be transmitted asynchronously.
                    SsfStreamOperationOutcome.Success => (null, ServerHttpResponse.NoContent()),
                    SsfStreamOperationOutcome.TooManyRequests => (null, ServerHttpResponse.TooManyRequests(
                        OAuthErrors.InvalidRequest,
                        "Verification requested more frequently than min_verification_interval permits.")),
                    SsfStreamOperationOutcome.NotFound => (null, ServerHttpResponse.NotFound()),

                    //Accepted and Forbidden are not outcomes a verification trigger can produce,
                    //but the delegate's declared return type still admits them, so they share
                    //NotFound's response rather than a 500 for an outcome no trigger rule uses.
                    SsfStreamOperationOutcome.Accepted => (null, ServerHttpResponse.NotFound()),
                    SsfStreamOperationOutcome.Forbidden => (null, ServerHttpResponse.NotFound()),

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


    /// <summary>
    /// The outcome of <see cref="AuthorizeAsync"/>: either the response the endpoint sends
    /// back for a denial, or the <see cref="Ssf.SsfReceiver"/> a permit bound the caller to —
    /// exactly one of the two is set.
    /// </summary>
    private sealed record SsfAuthorizationOutcome
    {
        /// <summary>The response to return for a denied request; <see langword="null"/> on a permit.</summary>
        public ServerHttpResponse? Denial { get; init; }

        /// <summary>
        /// The Receiver every store delegate for this request receives; <see langword="null"/>
        /// on a denial.
        /// </summary>
        public SsfReceiver? Receiver { get; init; }


        /// <summary>Builds a denied outcome carrying the response to send.</summary>
        /// <param name="response">The response the endpoint returns instead of calling its store.</param>
        /// <returns>An <see cref="SsfAuthorizationOutcome"/> with <see cref="Denial"/> set.</returns>
        public static SsfAuthorizationOutcome Denied(ServerHttpResponse response) =>
            new() { Denial = response };


        /// <summary>Builds a permitted outcome carrying the bound Receiver.</summary>
        /// <param name="receiver">The Receiver the store delegates for this request receive.</param>
        /// <returns>An <see cref="SsfAuthorizationOutcome"/> with <see cref="Receiver"/> set.</returns>
        public static SsfAuthorizationOutcome Permitted(SsfReceiver receiver) =>
            new() { Receiver = receiver };
    }


    //SSF 1.0 §8-3: every Stream Management API request calls this before its store
    //delegate runs. The Builder only materializes a candidate when the seam is
    //wired (fail-closed), so oauth.AuthorizeSsfRequestAsync is non-null on every
    //call reachable through dispatch; the null branch below is a defensive
    //fail-closed fallback, never an observed path.
    private static async ValueTask<SsfAuthorizationOutcome> AuthorizeAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        SsfRequestOperation operation,
        string requiredScope,
        string? streamId,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(oauth.AuthorizeSsfRequestAsync is null)
        {
            return SsfAuthorizationOutcome.Denied(await UnauthorizedWithChallengeAsync(
                server, registration, context, cancellationToken).ConfigureAwait(false));
        }

        IncomingRequest? req = context.IncomingRequest;
        if(req is null)
        {
            return SsfAuthorizationOutcome.Denied(await UnauthorizedWithChallengeAsync(
                server, registration, context, cancellationToken).ConfigureAwait(false));
        }

        SsfRequestDecision? decision;
        try
        {
            decision = await oauth.AuthorizeSsfRequestAsync(
                new SsfRequestEvaluation
                {
                    Operation = operation,
                    RequiredScope = requiredScope,
                    TenantId = registration.TenantId,
                    StreamId = streamId,
                    Request = req
                },
                registration, context, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch(Exception exception)
        {
            //The application's own authorization seam is a caller-registered delegate whose
            //failure vocabulary this endpoint cannot enumerate; any fault it raises surfaces
            //as this request's own server error, cancellation of its own token excepted
            //above, the same posture the pushed authorization request refusal takes for its
            //own transport delegate. No store delegate runs, and SSF 1.0 §8.1.1.1's error
            //table has no vocabulary for a seam fault, so this is a 500 outside it.
            _ = (System.Diagnostics.Activity.Current?.AddException(exception));

            return SsfAuthorizationOutcome.Denied(ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, "The Stream Management API request could not be authorized."));
        }

        //A seam that returns null is the same fail-closed case SsfRequestDecision.DenialReason
        //already documents for an unset reason: treated as NotAuthorizedForTenant, never a
        //NullReferenceException reaching the dispatcher.
        decision ??= new SsfRequestDecision { IsPermitted = false };

        if(decision.IsPermitted)
        {
            //decision.Receiver is set by every verdict built through
            //SsfRequestDecision.Permit(SsfReceiver); a permit assembled by hand without one is
            //the same misbehaving-seam case as a null decision, and fails closed rather than
            //reaching a store with no Receiver to bind. A Receiver without an identifier binds
            //nothing either, so it fails closed the same way.
            return decision.Receiver is { } receiver && !string.IsNullOrWhiteSpace(receiver.Id)
                ? SsfAuthorizationOutcome.Permitted(receiver)
                : SsfAuthorizationOutcome.Denied(ForbiddenForTenant());
        }

        RecordDenialDescription(decision.DenialDescription);

        return SsfAuthorizationOutcome.Denied(decision.DenialReason switch
        {
            SsfRequestDenialReason.AuthenticationRequired => await UnauthorizedWithChallengeAsync(
                server, registration, context, cancellationToken).ConfigureAwait(false),

            SsfRequestDenialReason.InsufficientScope => ServerHttpResponse.Forbidden(
                OAuthErrors.InvalidScope, "The granted scope does not permit this operation."),

            SsfRequestDenialReason.StreamNotAvailableToReceiver => ServerHttpResponse.NotFound(),

            //NotAuthorizedForTenant, and a denial with no reason set, share this fixed
            //§8.1.1.x 403 wording.
            _ => ForbiddenForTenant()
        });
    }


    /// <summary>
    /// Records the application's own <paramref name="hostDescription"/> for a denied Stream
    /// Management API request on the dispatch <see cref="System.Diagnostics.Activity"/>,
    /// for every <see cref="SsfRequestDenialReason"/> alike — mirroring how the pushed-request
    /// refusal keeps host detail off the wire and on the trace. A <see langword="null"/>
    /// description (the common case) records nothing.
    /// </summary>
    private static void RecordDenialDescription(string? hostDescription)
    {
        if(hostDescription is null)
        {
            return;
        }

        _ = (System.Diagnostics.Activity.Current?.AddEvent(
            new System.Diagnostics.ActivityEvent(
                OAuthEventNames.SsfRequestDenied,
                tags: new System.Diagnostics.ActivityTagsCollection
                {
                    [OAuthEventNames.SsfRequestDenialDescriptionTagName] = hostDescription
                })));
    }


    /// <summary>
    /// Builds the fixed, non-revealing 403 for <see cref="SsfRequestDenialReason.NotAuthorizedForTenant"/>
    /// (SSF 1.0 §8.1.1.1 Create Stream Errors and the parallel per-operation 403 rows). The
    /// application's own denial description, when it supplied one, already reached the trace
    /// through <see cref="RecordDenialDescription"/> — this response body is always the same
    /// fixed sentence, naming no tenant, client or stream.
    /// </summary>
    private static ServerHttpResponse ForbiddenForTenant() =>
        ServerHttpResponse.Forbidden(
            OAuthErrors.AccessDenied, "The Receiver is not authorized for this tenant.");


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
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
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
            issuer = oauth.ResolveIssuerAsync is not null
                ? (await oauth.ResolveIssuerAsync(registration, context, cancellationToken)
                    .ConfigureAwait(false))!
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
