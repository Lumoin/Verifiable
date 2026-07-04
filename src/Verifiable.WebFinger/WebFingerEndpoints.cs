using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Server;

namespace Verifiable.WebFinger;

/// <summary>
/// Endpoint builder for the WebFinger query endpoint per
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4">RFC 7033 §4</see>: a capability-gated
/// <c>GET /.well-known/webfinger</c> that resolves a <c>resource</c> query target (optionally filtered by
/// one or more <c>rel</c> parameters, per
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.3">RFC 7033 §4.3</see>) to a JSON Resource
/// Descriptor. Register at startup via <see cref="ServerConfiguration.EndpointBuilders"/>.
/// </summary>
/// <remarks>
/// <para>
/// Stateless: resolve → serialize, short-circuiting the dispatcher with the JRD (or a 400/404) exactly as
/// <see cref="WebFingerIntegration.ResolveWebFingerResourceAsync"/> — the ONE required application seam —
/// answers. The endpoint's own contribution is structural, not business logic: it enforces the
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.2">RFC 7033 §4.2</see> "resource exactly
/// once" MUST via <see cref="RequestFields.TryGetValue"/> (absent or repeated both fail closed to the
/// same read), threads every <c>rel</c> occurrence through unfiltered (§4.3), serializes the returned
/// descriptor through <see cref="JsonAppender"/> behind the serialization firewall, and stamps the
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-5">RFC 7033 §5</see>
/// <c>Access-Control-Allow-Origin</c> header on every outcome — success, 400, and 404 alike.
/// </para>
/// <para>
/// The endpoint never consults the <c>Accept</c> request header: <c>application/jrd+json</c> is the only
/// representation this library serves, so an absent, unsupported, or unrecognised <c>Accept</c> value is
/// silently ignored by construction (§4.2).
/// </para>
/// </remarks>
[DebuggerDisplay("WebFingerEndpoints")]
public static class WebFingerEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to <see cref="ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        EndpointServer? server = context.Server;

        //Fail-closed: the route materializes only when the registration carries the capability AND the
        //application wired its one required seam — only it knows the resource store the resolved
        //descriptor comes from.
        if(registration.AllowedCapabilities.Contains(WellKnownWebFingerCapabilityIdentifiers.Endpoint)
            && server?.WebFinger().ResolveWebFingerResourceAsync is not null)
        {
            candidates.Add(BuildQueryEndpoint());
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    /// <summary>
    /// Builds the <c>GET /.well-known/webfinger</c> query endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4">RFC 7033 §4</see>.
    /// </summary>
    private static EndpointCandidate BuildQueryEndpoint() =>
        new()
        {
            Name = WellKnownWebFingerEndpointNames.WebFinger,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownWebFingerCapabilityIdentifiers.Endpoint,
            StartsNewFlow = true,
            Kind = StatelessFlowKind.Instance,

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
                WebFingerIntegration webFinger = server.WebFinger();

                IRegistrationRecord? registration = context.Registration;
                if(registration is null)
                {
                    return (null, await WithCorsAsync(
                        ServerHttpResponse.ServerError(ServerErrors.ServerError, "Registration not found in context."),
                        webFinger, null, context, ct).ConfigureAwait(false));
                }

                //§4.2 MUST: 'resource' present exactly once and not malformed. TryGetValue's exactly-one
                //semantics fail closed for absent and repeated alike (RFC 6749 §3.1 rule made structural); a
                //present-but-empty value is rejected here as malformed rather than forwarded to the resolver.
                if(!fields.TryGetValue(WellKnownWebFingerValues.ResourceParameterName, out string? resource)
                    || string.IsNullOrWhiteSpace(resource))
                {
                    return (null, await WithCorsAsync(
                        ServerHttpResponse.BadRequest(
                            ServerErrors.InvalidRequest,
                            "The 'resource' parameter MUST be present exactly once and non-empty."),
                        webFinger, registration, context, ct).ConfigureAwait(false));
                }

                //§4.3 MAY: rel zero or more times. The resolver applies the filter — it alone knows how
                //to interpret a relation type against its resource store.
                IReadOnlyList<string> relFilters = fields.GetValues(WellKnownWebFingerValues.RelParameterName);

                //§5 MUST: the CORS header rides every response, including one produced when the application
                //resolver faults — so the resolver call is guarded and its failure still stamps the header.
                JsonResourceDescriptor? descriptor;
                try
                {
                    descriptor = await webFinger.ResolveWebFingerResourceAsync!(
                        resource, relFilters, registration, context, ct).ConfigureAwait(false);
                }
                catch(OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    return (null, await WithCorsAsync(
                        ServerHttpResponse.ServerError(ServerErrors.ServerError, "The WebFinger resource resolver failed."),
                        webFinger, registration, context, ct).ConfigureAwait(false));
                }

                //§4.2: 404 when the resource carries no information the resolver can vouch for.
                if(descriptor is null)
                {
                    return (null, await WithCorsAsync(
                        ServerHttpResponse.NotFound(), webFinger, registration, context, ct).ConfigureAwait(false));
                }

                string jrdJson = SerializeJrd(descriptor);
                ServerHttpResponse response = ServerHttpResponse.Ok(jrdJson, WellKnownWebFingerValues.JrdMediaType);

                return (null, await WithCorsAsync(
                    response, webFinger, registration, context, ct).ConfigureAwait(false));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Stamps the <c>Access-Control-Allow-Origin</c> header on <paramref name="response"/> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-5">RFC 7033 §5</see> — required on every
    /// response, success or failure alike. Falls back to the wildcard when no
    /// <see cref="ResolveCorsOriginDelegate"/> is wired, or when no registration was available to resolve
    /// against.
    /// </summary>
    private static async ValueTask<ServerHttpResponse> WithCorsAsync(
        ServerHttpResponse response,
        WebFingerIntegration webFinger,
        IRegistrationRecord? registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        string origin = registration is not null && webFinger.ResolveCorsOriginAsync is { } resolve
            ? await resolve(registration, context, cancellationToken).ConfigureAwait(false)
            : WellKnownWebFingerValues.AccessControlAllowOriginWildcard;

        return response.WithHeader(WellKnownWebFingerValues.AccessControlAllowOriginHeaderName, origin);
    }


    /// <summary>
    /// Serializes <paramref name="descriptor"/> as a JSON Resource Descriptor per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4">RFC 7033 §4.4</see>, by hand
    /// through <see cref="JsonAppender"/> — honouring the <c>Verifiable.WebFinger</c> serialization
    /// firewall (no <c>System.Text.Json</c> dependency in this assembly).
    /// </summary>
    private static string SerializeJrd(JsonResourceDescriptor descriptor)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;

            if(!string.IsNullOrEmpty(descriptor.Subject))
            {
                JsonAppender.AppendStringField(sb, WellKnownJrdMemberNames.Subject, descriptor.Subject, ref first);
            }

            if(descriptor.Aliases.Count > 0)
            {
                JsonAppender.AppendStringArrayField(sb, WellKnownJrdMemberNames.Aliases, descriptor.Aliases, ref first);
            }

            if(descriptor.Properties.Count > 0)
            {
                AppendNullableStringMapField(sb, WellKnownJrdMemberNames.Properties, descriptor.Properties, ref first);
            }

            if(descriptor.Links.Count > 0)
            {
                AppendLinksField(sb, descriptor.Links, ref first);
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
    /// Appends a <c>"key":{...}</c> field whose values may be a JSON string or JSON <c>null</c>, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.3">RFC 7033 §4.4.3</see> (also used
    /// for a link's <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.5">§4.4.4.5</see>
    /// <c>properties</c>). <see cref="JsonAppender.AppendStringField"/> cannot express a null value, so
    /// this writes the field by hand.
    /// </summary>
    private static void AppendNullableStringMapField(
        StringBuilder sb, string key, IReadOnlyDictionary<string, string?> map, ref bool first)
    {
        if(!first) { sb.Append(','); }
        first = false;

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, key);
        sb.Append("\":{");

        bool entryFirst = true;
        foreach(KeyValuePair<string, string?> entry in map)
        {
            if(!entryFirst) { sb.Append(','); }
            entryFirst = false;

            sb.Append('"');
            JsonAppender.AppendEscapedString(sb, entry.Key);
            sb.Append("\":");

            if(entry.Value is null)
            {
                sb.Append("null");
            }
            else
            {
                sb.Append('"');
                JsonAppender.AppendEscapedString(sb, entry.Value);
                sb.Append('"');
            }
        }

        sb.Append('}');
    }


    /// <summary>
    /// Appends the <c>links</c> array of link relation objects, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4">RFC 7033 §4.4.4</see>.
    /// </summary>
    private static void AppendLinksField(StringBuilder sb, IReadOnlyList<WebFingerLink> links, ref bool first)
    {
        if(!first) { sb.Append(','); }
        first = false;

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, WellKnownJrdMemberNames.Links);
        sb.Append("\":[");

        bool linkFirst = true;
        foreach(WebFingerLink link in links)
        {
            if(!linkFirst) { sb.Append(','); }
            linkFirst = false;

            AppendLink(sb, link);
        }

        sb.Append(']');
    }


    /// <summary>
    /// Appends one <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4">§4.4.4</see> link
    /// relation object. <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.1">§4.4.4.1</see>
    /// MUST: <c>rel</c> is required and single-valued — structural on <see cref="WebFingerLink.Rel"/>, so
    /// every link reaching here already carries one.
    /// </summary>
    private static void AppendLink(StringBuilder sb, WebFingerLink link)
    {
        sb.Append('{');
        bool first = true;

        JsonAppender.AppendStringField(sb, WellKnownJrdMemberNames.Rel, link.Rel, ref first);

        if(!string.IsNullOrEmpty(link.Type))
        {
            JsonAppender.AppendStringField(sb, WellKnownJrdMemberNames.Type, link.Type, ref first);
        }

        if(!string.IsNullOrEmpty(link.Href))
        {
            JsonAppender.AppendStringField(sb, WellKnownJrdMemberNames.Href, link.Href, ref first);
        }

        if(link.Titles.Count > 0)
        {
            AppendTitlesField(sb, link.Titles, ref first);
        }

        if(link.Properties.Count > 0)
        {
            AppendNullableStringMapField(sb, WellKnownJrdMemberNames.Properties, link.Properties, ref first);
        }

        sb.Append('}');
    }


    /// <summary>
    /// Appends the <c>titles</c> object mapping a language tag (or <c>und</c>) to a human-readable title,
    /// per <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4.4.4">RFC 7033 §4.4.4.4</see>.
    /// </summary>
    private static void AppendTitlesField(StringBuilder sb, IReadOnlyDictionary<string, string> titles, ref bool first)
    {
        if(!first) { sb.Append(','); }
        first = false;

        sb.Append('"');
        JsonAppender.AppendEscapedString(sb, WellKnownJrdMemberNames.Titles);
        sb.Append("\":{");

        bool titleFirst = true;
        foreach(KeyValuePair<string, string> title in titles)
        {
            JsonAppender.AppendStringField(sb, title.Key, title.Value, ref titleFirst);
        }

        sb.Append('}');
    }
}
