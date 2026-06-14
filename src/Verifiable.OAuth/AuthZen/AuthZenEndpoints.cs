using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server;

namespace Verifiable.OAuth.AuthZen;

/// <summary>
/// Endpoint builder for the OpenID AuthZEN Authorization API 1.0 Access
/// Evaluation API — <c>POST /access/v1/evaluation</c>. A Policy Enforcement
/// Point posts an <see cref="AccessEvaluationRequest"/>; the library parses it
/// (via the application's
/// <see cref="AuthorizationServerIntegration.ParseAccessEvaluationRequestAsync"/>),
/// asks the application's Policy Decision Point
/// (<see cref="AuthorizationServerIntegration.EvaluateAccessAsync"/>) for the
/// decision, and serialises the <c>{ "decision": &lt;bool&gt; }</c> response.
/// </summary>
/// <remarks>
/// <para>
/// Register at startup via
/// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>. Emitted for
/// registrations carrying
/// <see cref="WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi"/>.
/// </para>
/// <para>
/// <strong>Serialization firewall.</strong> The library owns the wire but not
/// JSON: the request body's arbitrary <c>properties</c> / <c>context</c>
/// objects are deserialised by the application's JSON stack behind
/// <see cref="ParseAccessEvaluationRequestDelegate"/>, and the simple
/// decision response is emitted by hand through <see cref="JsonAppender"/>.
/// No <c>System.Text.Json</c> dependency is taken on here.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthZenEndpoints")]
public static class AuthZenEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi))
        {
            candidates.Add(BuildAccessEvaluation());
            candidates.Add(BuildAccessEvaluations());

            //§7 Search APIs are OPTIONAL per-feature: each is active (and thus
            //advertised in the §9.1 metadata document) only when its seam is
            //wired. context.Server is guaranteed set before builders run
            //(EndpointChain.BuildForRequestAsync throws otherwise).
            EndpointServer? server = context.Server;
            if(server?.OAuth().SearchSubjectsAsync is not null)
            {
                candidates.Add(BuildSubjectSearch());
            }
            if(server?.OAuth().SearchResourcesAsync is not null)
            {
                candidates.Add(BuildResourceSearch());
            }
            if(server?.OAuth().SearchActionsAsync is not null)
            {
                candidates.Add(BuildActionSearch());
            }

            candidates.Add(BuildAuthZenConfiguration());
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    /// <summary>
    /// Builds the <c>POST /access/v1/evaluation</c> Access Evaluation endpoint
    /// per <see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN Authorization API 1.0</see>.
    /// Stateless: parse → decide → serialise, short-circuiting the dispatcher
    /// with the decision response.
    /// </summary>
    private static EndpointCandidate BuildAccessEvaluation() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthZenAccessEvaluation,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsPost(req.Method))
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
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                if(oauth.ParseAccessEvaluationRequestAsync is null
                    || oauth.EvaluateAccessAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "access_evaluation_endpoint requires "
                        + "AuthorizationServerIntegration.ParseAccessEvaluationRequestAsync and "
                        + "EvaluateAccessAsync to be configured."));
                }

                IncomingRequest? req = context.IncomingRequest;
                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Access Evaluation request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);

                AccessEvaluationRequest? request = await oauth.ParseAccessEvaluationRequestAsync(
                    requestBody, context, ct).ConfigureAwait(false);
                if(request is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Request body did not parse as a valid Access Evaluation request."));
                }

                AccessEvaluationDecision decision = await oauth.EvaluateAccessAsync(
                    request, registration, context, ct).ConfigureAwait(false);

                return (null, ServerHttpResponse.Ok(
                    BuildDecisionJson(decision), WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the <c>POST /access/v1/evaluations</c> Access Evaluations API
    /// (batch) endpoint per
    /// <see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN
    /// Authorization API 1.0 §6 (Access Evaluations API)</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Stateless: parse → resolve items against the request-level defaults →
    /// evaluate each through the shared PDP seam
    /// (<see cref="AuthorizationServerIntegration.EvaluateAccessAsync"/>),
    /// honouring the <c>options.evaluations_semantic</c> short-circuit →
    /// serialise the <c>{ "evaluations": [ … ] }</c> response. The library owns
    /// the batch composition and short-circuit semantics (spec-defined wire
    /// behaviour); the PDP seam owns each individual decision.
    /// </para>
    /// <para>
    /// The per-item parser and the decision serializer reuse the
    /// single-evaluation machinery — the batch endpoint adds only the
    /// defaults-resolution and the ordered loop.
    /// </para>
    /// </remarks>
    private static EndpointCandidate BuildAccessEvaluations() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthZenAccessEvaluations,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsPost(req.Method))
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
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                if(oauth.ParseAccessEvaluationsRequestAsync is null
                    || oauth.EvaluateAccessAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "access_evaluations_endpoint requires "
                        + "AuthorizationServerIntegration.ParseAccessEvaluationsRequestAsync and "
                        + "EvaluateAccessAsync to be configured."));
                }

                IncomingRequest? req = context.IncomingRequest;
                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Access Evaluations request body is missing."));
                }

                string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);

                AccessEvaluationsRequest? batch = await oauth.ParseAccessEvaluationsRequestAsync(
                    requestBody, context, ct).ConfigureAwait(false);
                if(batch is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Request body did not parse as a valid Access Evaluations request."));
                }

                if(!TryResolveEvaluationItems(batch, out List<AccessEvaluationRequest> items, out string? resolveError))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, resolveError!));
                }

                //§6 ordered evaluation with optional short-circuit. The
                //response array carries the items evaluated so far — for the
                //short-circuit semantics, that is up to and including the item
                //that stopped the run.
                AuthZenEvaluationsSemantic semantic =
                    batch.Options?.Semantic ?? AuthZenEvaluationsSemantic.ExecuteAll;

                List<AccessEvaluationDecision> decisions = new(items.Count);
                foreach(AccessEvaluationRequest item in items)
                {
                    AccessEvaluationDecision decision = await oauth.EvaluateAccessAsync(
                        item, registration, context, ct).ConfigureAwait(false);
                    decisions.Add(decision);

                    if(semantic == AuthZenEvaluationsSemantic.DenyOnFirstDeny && !decision.Decision)
                    {
                        break;
                    }
                    if(semantic == AuthZenEvaluationsSemantic.PermitOnFirstPermit && decision.Decision)
                    {
                        break;
                    }
                }

                return (null, ServerHttpResponse.Ok(
                    BuildBatchJson(decisions), WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Resolves the <c>evaluations</c> array of <paramref name="batch"/> into
    /// full <see cref="AccessEvaluationRequest"/>s by overlaying each
    /// <see cref="AccessEvaluationItem"/> over the request-level defaults
    /// (§6: a present per-item entity replaces the default entirely). An empty
    /// <c>evaluations</c> array resolves to a single evaluation over the
    /// defaults. Returns <see langword="false"/> with a 400-worthy
    /// <paramref name="error"/> when a resolved item lacks a required Subject,
    /// Action, or Resource.
    /// </summary>
    private static bool TryResolveEvaluationItems(
        AccessEvaluationsRequest batch,
        out List<AccessEvaluationRequest> items,
        out string? error)
    {
        IReadOnlyList<AccessEvaluationItem> entries = batch.Evaluations.Count > 0
            ? batch.Evaluations
            //§6: an absent or empty evaluations array behaves as a single
            //Access Evaluation over the request-level defaults. One empty
            //overlay yields exactly that.
            : [new AccessEvaluationItem()];

        items = new List<AccessEvaluationRequest>(entries.Count);
        for(int i = 0; i < entries.Count; ++i)
        {
            AccessEvaluationItem entry = entries[i];

            AuthZenSubject? subject = entry.Subject ?? batch.Subject;
            AuthZenAction? action = entry.Action ?? batch.Action;
            AuthZenResource? resource = entry.Resource ?? batch.Resource;
            IReadOnlyDictionary<string, object>? itemContext = entry.Context ?? batch.Context;

            if(subject is null || action is null || resource is null)
            {
                items = [];
                error = $"evaluations[{i}] is missing a subject, action, or resource "
                    + "after applying request-level defaults.";
                return false;
            }

            items.Add(new AccessEvaluationRequest
            {
                Subject = subject,
                Action = action,
                Resource = resource,
                Context = itemContext,
            });
        }

        error = null;
        return true;
    }


    /// <summary>
    /// Serialises the §6 Access Evaluations response body
    /// <c>{ "evaluations": [ { "decision": &lt;bool&gt;, "context"?: { … } }, … ] }</c>.
    /// The top-level <c>decision</c> key is omitted per §6 when the
    /// <c>evaluations</c> array is present. Built by hand through
    /// <see cref="JsonAppender"/> to honour the serialization firewall.
    /// </summary>
    private static string BuildBatchJson(List<AccessEvaluationDecision> decisions)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append("{\"");
            JsonAppender.AppendEscapedString(sb, AuthZenFieldNames.Evaluations);
            sb.Append("\":[");

            for(int i = 0; i < decisions.Count; ++i)
            {
                if(i > 0)
                {
                    sb.Append(',');
                }

                AppendDecisionObject(sb, decisions[i]);
            }

            sb.Append("]}");

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Builds the <c>POST /access/v1/search/subject</c> Subject Search endpoint
    /// per <see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN
    /// Authorization API 1.0 §7 (Search API)</see>. Stateless: parse → enumerate
    /// via <see cref="AuthorizationServerIntegration.SearchSubjectsAsync"/> →
    /// serialise <c>{ "page": { … }, "results": [ … ] }</c>.
    /// </summary>
    private static EndpointCandidate BuildSubjectSearch() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthZenSearchSubject,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = SearchMatcher,

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Client registration not found in context."));
                }

                if(oauth.SearchSubjectsAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "search_subject_endpoint requires "
                        + "AuthorizationServerIntegration.SearchSubjectsAsync to be configured."));
                }

                (AccessSearchRequest? request, ServerHttpResponse? error) =
                    await ReadSearchRequestAsync(server, context, ct).ConfigureAwait(false);
                if(error is not null) { return (null, error); }

                //§7 Subject Search: the subject carries the type to enumerate.
                if(request!.Subject is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Subject Search requires a subject carrying the type to enumerate."));
                }

                SubjectSearchResult result = await oauth.SearchSubjectsAsync(
                    request, registration, context, ct).ConfigureAwait(false);

                return (null, ServerHttpResponse.Ok(
                    BuildSearchJson(result.Page, result.Context, result.Results, AppendSubjectEntity),
                    WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the <c>POST /access/v1/search/resource</c> Resource Search
    /// endpoint per §7. Stateless: parse → enumerate via
    /// <see cref="AuthorizationServerIntegration.SearchResourcesAsync"/> →
    /// serialise the §7 result envelope.
    /// </summary>
    private static EndpointCandidate BuildResourceSearch() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthZenSearchResource,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = SearchMatcher,

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Client registration not found in context."));
                }

                if(oauth.SearchResourcesAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "search_resource_endpoint requires "
                        + "AuthorizationServerIntegration.SearchResourcesAsync to be configured."));
                }

                (AccessSearchRequest? request, ServerHttpResponse? error) =
                    await ReadSearchRequestAsync(server, context, ct).ConfigureAwait(false);
                if(error is not null) { return (null, error); }

                //§7 Resource Search: the resource carries the type to enumerate.
                if(request!.Resource is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Resource Search requires a resource carrying the type to enumerate."));
                }

                ResourceSearchResult result = await oauth.SearchResourcesAsync(
                    request, registration, context, ct).ConfigureAwait(false);

                return (null, ServerHttpResponse.Ok(
                    BuildSearchJson(result.Page, result.Context, result.Results, AppendResourceEntity),
                    WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the <c>POST /access/v1/search/action</c> Action Search endpoint
    /// per §7 — enumerates the actions a subject may perform on a resource.
    /// Stateless: parse → enumerate via
    /// <see cref="AuthorizationServerIntegration.SearchActionsAsync"/> →
    /// serialise the §7 result envelope.
    /// </summary>
    private static EndpointCandidate BuildActionSearch() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthZenSearchAction,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = SearchMatcher,

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Client registration not found in context."));
                }

                if(oauth.SearchActionsAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "search_action_endpoint requires "
                        + "AuthorizationServerIntegration.SearchActionsAsync to be configured."));
                }

                (AccessSearchRequest? request, ServerHttpResponse? error) =
                    await ReadSearchRequestAsync(server, context, ct).ConfigureAwait(false);
                if(error is not null) { return (null, error); }

                //§7 Action Search carries no action — the response IS the set of
                //permitted actions, so there is no per-endpoint required entity
                //beyond a parseable body.
                ActionSearchResult result = await oauth.SearchActionsAsync(
                    request!, registration, context, ct).ConfigureAwait(false);

                return (null, ServerHttpResponse.Ok(
                    BuildSearchJson(result.Page, result.Context, result.Results, AppendActionEntity),
                    WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// The shared POST + path matcher for the three §7 Search endpoints.
    /// </summary>
    private static readonly MatchRequestDelegate SearchMatcher = static (fields, context, endpoint, ct) =>
    {
        IncomingRequest? req = context.IncomingRequest;
        if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
        if(!WellKnownHttpMethods.IsPost(req.Method))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }
        if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
        {
            return ValueTask.FromResult<MatchPayload?>(null);
        }

        return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
    };


    /// <summary>
    /// Reads and parses the §7 Search request body shared by all three search
    /// endpoints: validates the parser is configured, reads the POST body, and
    /// delegates JSON parsing to
    /// <see cref="AuthorizationServerIntegration.ParseAccessSearchRequestAsync"/>.
    /// Returns the parsed request, or an early HTTP error response (500 if the
    /// parser is unconfigured, 400 for a missing or unparseable body).
    /// </summary>
    private static async ValueTask<(AccessSearchRequest? Request, ServerHttpResponse? Error)> ReadSearchRequestAsync(
        EndpointServer server, ExchangeContext context, CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(oauth.ParseAccessSearchRequestAsync is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "AuthZEN search endpoints require "
                + "AuthorizationServerIntegration.ParseAccessSearchRequestAsync to be configured."));
        }

        IncomingRequest? req = context.IncomingRequest;
        if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "Search request body is missing."));
        }

        string requestBody = Encoding.UTF8.GetString(req.Body.Bytes.Span);

        AccessSearchRequest? request = await oauth.ParseAccessSearchRequestAsync(
            requestBody, context, cancellationToken).ConfigureAwait(false);
        if(request is null)
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "Request body did not parse as a valid Search request."));
        }

        return (request, null);
    }


    /// <summary>
    /// Serialises a §7 Search response envelope
    /// <c>{ "page": { "next_token": …, … }, "context"?: { … }, "results": [ … ] }</c>.
    /// Each result element is written by <paramref name="appendEntity"/> (a
    /// capture-free static method group per entity type). Built by hand through
    /// <see cref="JsonAppender"/> to honour the serialization firewall.
    /// </summary>
    private static string BuildSearchJson<TEntity>(
        AccessSearchPage page,
        IReadOnlyDictionary<string, object>? context,
        IReadOnlyList<TEntity> results,
        Action<StringBuilder, TEntity> appendEntity)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');

            AppendPageObject(sb, page);

            if(context is { Count: > 0 } responseContext)
            {
                sb.Append(",\"");
                JsonAppender.AppendEscapedString(sb, AuthZenFieldNames.Context);
                sb.Append("\":");
                JsonAppender.AppendObject(sb, responseContext);
            }

            sb.Append(",\"");
            JsonAppender.AppendEscapedString(sb, AuthZenFieldNames.Results);
            sb.Append("\":[");

            for(int i = 0; i < results.Count; ++i)
            {
                if(i > 0)
                {
                    sb.Append(',');
                }

                appendEntity(sb, results[i]);
            }

            sb.Append("]}");

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Appends the §7 response <c>"page": { … }</c> object as the first member
    /// of the envelope. <c>next_token</c> is always emitted (empty string =
    /// end of results); <c>count</c> and <c>total</c> are emitted when present.
    /// </summary>
    private static void AppendPageObject(StringBuilder sb, AccessSearchPage page)
    {
        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, AuthZenFieldNames.Page);
        sb.Append("\":{");

        bool first = true;
        JsonAppender.AppendStringField(sb, AuthZenFieldNames.NextToken, page.NextToken ?? "", ref first);

        if(page.Count is long count)
        {
            JsonAppender.AppendInt64Field(sb, AuthZenFieldNames.Count, count, ref first);
        }
        if(page.Total is long total)
        {
            JsonAppender.AppendInt64Field(sb, AuthZenFieldNames.Total, total, ref first);
        }

        //§7 OPTIONAL implementation-specific page attributes, nested under page.
        AppendPropertiesIfAny(sb, page.Properties);

        sb.Append('}');
    }


    /// <summary>Appends a Subject entity <c>{ "type": …, "id": …, "properties"?: { … } }</c>.</summary>
    private static void AppendSubjectEntity(StringBuilder sb, AuthZenSubject subject)
    {
        sb.Append('{');

        bool first = true;
        JsonAppender.AppendStringField(sb, AuthZenFieldNames.Type, subject.Type, ref first);
        JsonAppender.AppendStringField(sb, AuthZenFieldNames.Id, subject.Id, ref first);
        AppendPropertiesIfAny(sb, subject.Properties);

        sb.Append('}');
    }


    /// <summary>Appends a Resource entity <c>{ "type": …, "id": …, "properties"?: { … } }</c>.</summary>
    private static void AppendResourceEntity(StringBuilder sb, AuthZenResource resource)
    {
        sb.Append('{');

        bool first = true;
        JsonAppender.AppendStringField(sb, AuthZenFieldNames.Type, resource.Type, ref first);
        JsonAppender.AppendStringField(sb, AuthZenFieldNames.Id, resource.Id, ref first);
        AppendPropertiesIfAny(sb, resource.Properties);

        sb.Append('}');
    }


    /// <summary>Appends an Action entity <c>{ "name": …, "properties"?: { … } }</c>.</summary>
    private static void AppendActionEntity(StringBuilder sb, AuthZenAction action)
    {
        sb.Append('{');

        bool first = true;
        JsonAppender.AppendStringField(sb, AuthZenFieldNames.Name, action.Name, ref first);
        AppendPropertiesIfAny(sb, action.Properties);

        sb.Append('}');
    }


    /// <summary>
    /// Appends a <c>,"properties": { … }</c> field when the entity carries a
    /// non-empty property bag. Assumes the entity object already has at least
    /// one preceding member (so the leading comma is always correct).
    /// </summary>
    private static void AppendPropertiesIfAny(StringBuilder sb, IReadOnlyDictionary<string, object>? properties)
    {
        if(properties is { Count: > 0 } bag)
        {
            sb.Append(",\"");
            JsonAppender.AppendEscapedString(sb, AuthZenFieldNames.Properties);
            sb.Append("\":");
            JsonAppender.AppendObject(sb, bag);
        }
    }


    /// <summary>
    /// Builds the <c>GET /.well-known/authzen-configuration</c> Policy
    /// Decision Point metadata endpoint per
    /// <see href="https://openid.net/specs/authorization-api-1_0.html">AuthZEN
    /// Authorization API 1.0 §9.1 (Policy Decision Point Metadata)</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Stateless: <see cref="ServerEndpoint.BuildInputAsync"/> resolves the
    /// PDP identifier via
    /// <see cref="AuthorizationServerIntegration.ResolveIssuerAsync"/>
    /// (falling back to the library default), reads each AuthZEN endpoint URL
    /// off the per-request <see cref="EndpointChain"/> the dispatcher placed on
    /// the context, hand-builds the JSON document, and short-circuits the
    /// dispatcher with the metadata response.
    /// <see cref="ServerEndpoint.BuildResponse"/> is never reached.
    /// </para>
    /// <para>
    /// §9.1 <c>policy_decision_point</c> and <c>access_evaluation_endpoint</c>
    /// are REQUIRED; the batch and search endpoints are OPTIONAL and are
    /// advertised only when the corresponding endpoint is active on the chain
    /// for this request. Like the federation Entity Configuration, the library
    /// never composes a path — each advertised URL is the same
    /// <see cref="ServerEndpoint.ResolvedUri"/> the matcher binds to, so the
    /// document cannot drift from what the PDP actually serves.
    /// </para>
    /// </remarks>
    private static EndpointCandidate BuildAuthZenConfiguration() =>
        new()
        {
            Name = WellKnownEndpointNames.AuthZenConfiguration,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.AuthZenAuthorizationApi,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //DiscoveryMetadataKey null — the AuthZEN metadata document is itself
            //a well-known document; it is not advertised inside the OAuth
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
                EndpointServer server = context.Server!;
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
                        "EndpointChain not on context for AuthZEN metadata emission. "
                        + "DispatchAsync sets this; this code path is only reachable "
                        + "through dispatch."));
                }

                //§9.1: policy_decision_point is the PDP identifier — a URL,
                //the AuthZEN analogue of the OAuth issuer. Resolve it through
                //the same seam the discovery document uses so a co-located
                //AS+PDP advertises one consistent identity, and a standalone
                //PDP overrides ResolveIssuerAsync per tenant.
                Uri policyDecisionPoint;
                try
                {
                    policyDecisionPoint = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false))!
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Policy Decision Point identifier (issuer) not found in context."));
                }

                //§9.1 capabilities — application-supplied IANA URNs the library
                //cannot derive from the chain.
                AuthZenMetadataContribution contribution =
                    oauth.ContributeAuthZenMetadataAsync is null
                        ? AuthZenMetadataContribution.Empty
                        : await oauth.ContributeAuthZenMetadataAsync(
                            registration, context, ct).ConfigureAwait(false);

                IReadOnlyList<string>? capabilities =
                    contribution.Capabilities is { Count: > 0 } caps ? caps : null;

                //§9.1 signed_metadata — the library assembles the metadata claim
                //set and drops out to the application's signer (which owns the
                //key and algorithm). The same chain-resolved values go into both
                //the plain document and the signed JWT, so they cannot diverge.
                string? signedMetadata = null;
                if(oauth.SignAuthZenMetadataAsync is not null)
                {
                    JwtPayload claims = BuildMetadataClaims(policyDecisionPoint, chain, capabilities);
                    signedMetadata = await oauth.SignAuthZenMetadataAsync(
                        claims, registration, context, ct).ConfigureAwait(false);
                }

                string metadataJson = BuildMetadataJson(
                    policyDecisionPoint, chain, capabilities, signedMetadata);

                return (null, ServerHttpResponse.Ok(
                    metadataJson, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Serialises the AuthZEN §9.1 Policy Decision Point metadata document:
    /// the REQUIRED <c>policy_decision_point</c> identifier, each AuthZEN
    /// endpoint URL active on the per-request <paramref name="chain"/> (mapped
    /// to its §9.1 metadata field by <see cref="MetadataFieldForEndpoint"/>),
    /// the optional <c>capabilities</c> array, and the optional
    /// <c>signed_metadata</c> JWT. Built by hand through
    /// <see cref="JsonAppender"/> to honour the <c>Verifiable.OAuth</c>
    /// serialization firewall.
    /// </summary>
    private static string BuildMetadataJson(
        Uri policyDecisionPoint,
        EndpointChain chain,
        IReadOnlyList<string>? capabilities,
        string? signedMetadata)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');

            bool first = true;
            JsonAppender.AppendUriField(
                sb, AuthZenMetadataParameterNames.PolicyDecisionPoint, policyDecisionPoint, ref first);

            //Each advertised endpoint URL is read straight off the chain the
            //dispatcher built, so the document advertises exactly the endpoints
            //active for this request and the URL is the one the matcher binds
            //to — no path composition, no drift.
            foreach(ServerEndpoint chainEndpoint in chain)
            {
                string? metadataField = MetadataFieldForEndpoint(chainEndpoint.Name);
                if(metadataField is null) { continue; }

                JsonAppender.AppendStringField(
                    sb, metadataField, chainEndpoint.ResolvedUri.ToString(), ref first);
            }

            if(capabilities is { Count: > 0 })
            {
                JsonAppender.AppendStringArrayField(
                    sb, AuthZenMetadataParameterNames.Capabilities, capabilities, ref first);
            }

            if(!string.IsNullOrEmpty(signedMetadata))
            {
                JsonAppender.AppendStringField(
                    sb, AuthZenMetadataParameterNames.SignedMetadata, signedMetadata, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Assembles the §9.1 metadata claim set handed to the
    /// <see cref="AuthorizationServerIntegration.SignAuthZenMetadataAsync"/>
    /// signer — the same <c>policy_decision_point</c>, endpoint URLs, and
    /// <c>capabilities</c> the plain document carries, so the signed JWT cannot
    /// diverge from the advertised document. The signer adds the spec-required
    /// <c>iss</c> claim (the PDP identifier).
    /// </summary>
    private static JwtPayload BuildMetadataClaims(
        Uri policyDecisionPoint, EndpointChain chain, IReadOnlyList<string>? capabilities)
    {
        //OriginalString matches the plain document's AppendUriField emission, so
        //the signed claim and the advertised value are byte-identical. The claim
        //set is a JwtPayload (the JOSE payload leaf) — it IS the JWT payload the
        //application will sign, so it carries that role in its type.
        JwtPayload claims = new()
        {
            [AuthZenMetadataParameterNames.PolicyDecisionPoint] = policyDecisionPoint.OriginalString
        };

        foreach(ServerEndpoint chainEndpoint in chain)
        {
            string? metadataField = MetadataFieldForEndpoint(chainEndpoint.Name);
            if(metadataField is null) { continue; }

            claims[metadataField] = chainEndpoint.ResolvedUri.ToString();
        }

        if(capabilities is { Count: > 0 })
        {
            claims[AuthZenMetadataParameterNames.Capabilities] = capabilities;
        }

        return claims;
    }


    /// <summary>
    /// Maps an AuthZEN endpoint's <see cref="ServerEndpoint.Name"/> to its
    /// AuthZEN §9.1 metadata field name, or <see langword="null"/> for an
    /// endpoint the metadata document does not advertise. New AuthZEN
    /// endpoints (batch evaluations, the search APIs) add a case here as they
    /// land.
    /// </summary>
    private static string? MetadataFieldForEndpoint(string endpointName)
    {
        if(string.Equals(endpointName, WellKnownEndpointNames.AuthZenAccessEvaluation, StringComparison.Ordinal))
        {
            return AuthZenMetadataParameterNames.AccessEvaluationEndpoint;
        }
        if(string.Equals(endpointName, WellKnownEndpointNames.AuthZenAccessEvaluations, StringComparison.Ordinal))
        {
            return AuthZenMetadataParameterNames.AccessEvaluationsEndpoint;
        }
        if(string.Equals(endpointName, WellKnownEndpointNames.AuthZenSearchSubject, StringComparison.Ordinal))
        {
            return AuthZenMetadataParameterNames.SearchSubjectEndpoint;
        }
        if(string.Equals(endpointName, WellKnownEndpointNames.AuthZenSearchResource, StringComparison.Ordinal))
        {
            return AuthZenMetadataParameterNames.SearchResourceEndpoint;
        }
        if(string.Equals(endpointName, WellKnownEndpointNames.AuthZenSearchAction, StringComparison.Ordinal))
        {
            return AuthZenMetadataParameterNames.SearchActionEndpoint;
        }

        return null;
    }


    /// <summary>
    /// Serialises an <see cref="AccessEvaluationDecision"/> to the AuthZEN
    /// response body <c>{ "decision": &lt;bool&gt; }</c>, with an optional
    /// <c>context</c> object. Built by hand through <see cref="JsonAppender"/>
    /// to honour the <c>Verifiable.OAuth</c> serialization firewall.
    /// </summary>
    private static string BuildDecisionJson(AccessEvaluationDecision decision)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            AppendDecisionObject(sb, decision);

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Appends one decision object <c>{ "decision": &lt;bool&gt;, "context"?: { … } }</c>
    /// to <paramref name="sb"/>. Shared by the single-evaluation response and
    /// each element of the batch <c>evaluations</c> array.
    /// </summary>
    private static void AppendDecisionObject(StringBuilder sb, AccessEvaluationDecision decision)
    {
        sb.Append('{');

        bool first = true;
        JsonAppender.AppendBoolField(sb, AuthZenFieldNames.Decision, decision.Decision, ref first);

        if(decision.Context is { Count: > 0 } responseContext)
        {
            sb.Append(",\"");
            JsonAppender.AppendEscapedString(sb, AuthZenFieldNames.Context);
            sb.Append("\":");
            JsonAppender.AppendObject(sb, responseContext);
        }

        sb.Append('}');
    }
}
