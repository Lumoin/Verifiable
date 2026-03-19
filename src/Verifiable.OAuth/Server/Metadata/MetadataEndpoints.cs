using System.Diagnostics;
using System.Globalization;
using System.Text;
using Verifiable.JCose;

using Verifiable.OAuth.Server.Routing;
using Verifiable.OAuth.Server.Pipeline;
namespace Verifiable.OAuth.Server.Metadata;

/// <summary>
/// Endpoint builder module for JWKS and Discovery metadata endpoints.
/// </summary>
/// <remarks>
/// <para>
/// Register at startup via <see cref="AuthorizationServer.EndpointBuilders"/>:
/// </para>
/// <code>
/// server.EndpointBuilders.AddRange([
///     MetadataEndpoints.Builder,
///     AuthCodeEndpoints.Builder,
///     Oid4VpEndpoints.Builder
/// ]);
/// </code>
/// <para>
/// Produces endpoints only for registrations that have
/// <see cref="ServerCapabilityName.JwksEndpoint"/> or
/// <see cref="ServerCapabilityName.DiscoveryEndpoint"/> capabilities.
/// </para>
/// <para>
/// The discovery endpoint composes URLs by asking the application via
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>. The
/// library never composes paths from templates — each URL the discovery document
/// advertises is the URL the application actually serves.
/// </para>
/// <para>
/// <strong>JSON wire format and the serialization firewall.</strong> The
/// discovery and JWKS response bodies are written as JSON by hand using
/// <see cref="StringBuilder"/> rather than through a serializer. This is
/// deliberate. <c>Verifiable.OAuth</c> takes no dependency on
/// <c>Verifiable.Json</c>, on <c>System.Text.Json</c>, or on any other JSON
/// library, and the project's banned-symbol analyzer enforces this. The
/// library does not impose a JSON implementation on the application.
/// </para>
/// <para>
/// The wire shapes here are RFC-defined and stable: the discovery document
/// per
/// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414</see>
/// (and the OIDC Discovery profile that extends it) and the JWKS document
/// per
/// <see href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</see>. The
/// fields are well-known property names with primitive values (strings,
/// booleans, integers) plus arrays of strings; nested or schema-variable
/// structure is not used. For shapes like that, manual
/// <see cref="StringBuilder"/> construction is the simplest path that
/// respects the firewall and stays AOT-safe without source-generator
/// context maintenance.
/// </para>
/// <para>
/// Application-contributed discovery fields arrive through
/// <see cref="AuthorizationServerIntegration.ContributeDiscoveryFieldsAsync"/>
/// as already-typed values; the helper
/// <see cref="AppendContributedField"/> emits each according to its
/// runtime CLR type (string, bool, list of strings, otherwise
/// <see cref="IFormattable"/> with invariant culture). The application is
/// free to compute those values with any serializer; it just hands the
/// library typed primitives.
/// </para>
/// </remarks>
[DebuggerDisplay("MetadataEndpoints")]
public static class MetadataEndpoints
{
    private const string Get = "GET";


    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="AuthorizationServer.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, server) =>
    {
        List<ServerEndpoint> endpoints = [];

        if(registration.IsCapabilityAllowed(ServerCapabilityName.JwksEndpoint))
        {
            endpoints.Add(BuildJwks());
        }

        if(registration.IsCapabilityAllowed(ServerCapabilityName.DiscoveryEndpoint))
        {
            endpoints.Add(BuildDiscovery());
        }

        return endpoints;
    };


    /// <summary>
    /// Builds the JWKS endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The endpoint is stateless: <see cref="ServerEndpoint.BuildInputAsync"/>
    /// resolves the <see cref="JwksDocument"/> via the application's
    /// <see cref="AuthorizationServerCryptography.BuildJwksDocumentAsync"/>
    /// delegate, then serializes it to JSON via <see cref="BuildJwksJson"/>
    /// and short-circuits the dispatcher with an early
    /// <see cref="ServerHttpResponse.Ok(string, string)"/> result.
    /// <see cref="ServerEndpoint.BuildResponse"/> is never reached.
    /// </para>
    /// <para>
    /// The serialization is hand-written; see the serialization-firewall
    /// paragraph in the remarks on <see cref="MetadataEndpoints"/> for the
    /// rationale.
    /// </para>
    /// </remarks>
    private static ServerEndpoint BuildJwks() =>
        new()
        {
            Name = "Metadata.Jwks",
            HttpMethod = Get,
            Capability = ServerCapabilityName.JwksEndpoint,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            //Acceptance test: GET to /jwks for this registration when JWKS is
            //in the registration's capability set. Path comparison goes through
            //ServerPaths.IsEndpoint so query strings, fragments, and trailing
            //slashes are all handled uniformly.
            MatchesRequest = static (fields, context, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!string.Equals(req.Method, Get, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRegistration? registration = context.Registration;
                if(registration is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!registration.IsCapabilityAllowed(ServerCapabilityName.JwksEndpoint))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!ServerPaths.IsEndpoint(req.Path, ServerEndpointPaths.Jwks, registration.TenantId.Value))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            //The JWKS endpoint is stateless — it does not step the PDA. BuildInputAsync
            //builds the complete response and returns it as an early exit. BuildResponse
            //is never reached.
            BuildInputAsync = static async (fields, context, currentState, server, ct) =>
            {
                if(server.Cryptography.BuildJwksDocumentAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "BuildJwksDocumentAsync is not configured."));
                }

                ClientRegistration? registration = context.Registration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                JwksDocument jwks = await server.Cryptography.BuildJwksDocumentAsync(
                    registration, context, ct).ConfigureAwait(false);

                string body = BuildJwksJson(jwks);

                return (null, ServerHttpResponse.Ok(body, "application/json"));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the OAuth/OIDC discovery endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414</see>
    /// and the OpenID Connect Discovery 1.0 profile that extends it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The endpoint is stateless:
    /// <see cref="ServerEndpoint.BuildInputAsync"/> resolves the issuer via
    /// <see cref="AuthorizationServerIntegration.ResolveIssuerAsync"/>
    /// (falling back to <see cref="DefaultIssuerResolver"/>), then asks the
    /// application's
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// for the absolute URL of each capability-gated endpoint, optionally
    /// merges fields from
    /// <see cref="AuthorizationServerIntegration.ContributeDiscoveryFieldsAsync"/>,
    /// and short-circuits the dispatcher with an early
    /// <see cref="ServerHttpResponse.Ok(string, string)"/> result.
    /// <see cref="ServerEndpoint.BuildResponse"/> is never reached.
    /// </para>
    /// <para>
    /// The library never composes paths; each advertised URL is the URL the
    /// application returns. Without
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// the document still returns valid JSON carrying just the issuer plus
    /// any application-contributed fields.
    /// </para>
    /// <para>
    /// The JSON body is assembled by hand using <see cref="StringBuilder"/>
    /// via the helpers <see cref="AppendEndpointAsync"/>,
    /// <see cref="AppendField"/>, and <see cref="AppendContributedField"/>.
    /// See the serialization-firewall paragraph in the remarks on
    /// <see cref="MetadataEndpoints"/> for the rationale.
    /// </para>
    /// </remarks>
    private static ServerEndpoint BuildDiscovery() =>
        new()
        {
            Name = "Metadata.Discovery",
            HttpMethod = Get,
            Capability = ServerCapabilityName.DiscoveryEndpoint,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            //Acceptance test: GET to the discovery URL for this registration
            //when Discovery is in the registration's capability set.
            MatchesRequest = static (fields, context, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!string.Equals(req.Method, Get, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRegistration? registration = context.Registration;
                if(registration is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!registration.IsCapabilityAllowed(ServerCapabilityName.DiscoveryEndpoint))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!ServerPaths.IsEndpoint(req.Path, ServerEndpointPaths.Discovery, registration.TenantId.Value))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, server, ct) =>
            {
                ClientRegistration? registration = context.Registration;
                if(registration is null)
                {
                    return (null,
                        ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            "Client registration not found in context."));
                }

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
                    return (null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "Issuer URI not found in context."));
                }

                var sb = new StringBuilder();
                sb.Append('{');

                string issuerValue = issuer.GetLeftPart(UriPartial.Authority);
                sb.Append("\"issuer\":\"");
                sb.Append(issuerValue);
                sb.Append('"');

                //Endpoint URLs are emitted only when the application has wired
                //ResolveEndpointUriAsync. Without it the library cannot know what
                //paths the application serves; the discovery document still
                //returns valid JSON with only the issuer field, plus any
                //application-contributed fields. Wire ResolveEndpointUriAsync to
                //advertise jwks_uri, authorization_endpoint, token_endpoint, and
                //the rest.
                if(server.Integration.ResolveEndpointUriAsync is not null)
                {
                    //For each advertisable capability the registration has, ask
                    //the application for the absolute URL keyed by the metadata
                    //field name and emit it. The library never builds paths.
                    await AppendEndpointAsync(
                        sb, server, registration, context,
                        ServerCapabilityName.JwksEndpoint,
                        AuthorizationServerMetadataKeys.JwksUri, ct).ConfigureAwait(false);

                    await AppendEndpointAsync(
                        sb, server, registration, context,
                        ServerCapabilityName.PushedAuthorization,
                        AuthorizationServerMetadataKeys.PushedAuthorizationRequestEndpoint, ct).ConfigureAwait(false);

                    await AppendEndpointAsync(
                        sb, server, registration, context,
                        ServerCapabilityName.AuthorizationCode,
                        AuthorizationServerMetadataKeys.AuthorizationEndpoint, ct).ConfigureAwait(false);

                    bool hasToken =
                        registration.IsCapabilityAllowed(ServerCapabilityName.AuthorizationCode) ||
                        registration.IsCapabilityAllowed(ServerCapabilityName.ClientCredentials) ||
                        registration.IsCapabilityAllowed(ServerCapabilityName.TokenExchange);

                    if(hasToken)
                    {
                        //The token endpoint applies whenever any token-issuing
                        //grant is enabled; it is not capability-scoped, so the
                        //application is asked for the URL keyed by the discovery
                        //metadata field.
                        Uri? tokenUri = await server.Integration.ResolveEndpointUriAsync(
                            AuthorizationServerMetadataKeys.TokenEndpoint, registration, context, ct)
                            .ConfigureAwait(false);
                        if(tokenUri is not null)
                        {
                            AppendField(sb, AuthorizationServerMetadataKeys.TokenEndpoint, tokenUri.ToString());
                        }
                    }

                    await AppendEndpointAsync(
                        sb, server, registration, context,
                        ServerCapabilityName.TokenRevocation,
                        AuthorizationServerMetadataKeys.RevocationEndpoint, ct).ConfigureAwait(false);
                }

                //Application-supplied additional fields merged after the base set.
                if(server.Integration.ContributeDiscoveryFieldsAsync is not null)
                {
                    DiscoveryDocumentContribution contributed =
                        await server.Integration.ContributeDiscoveryFieldsAsync(
                            registration, context, ct).ConfigureAwait(false);

                    foreach(DiscoveryField field in contributed.Fields)
                    {
                        AppendContributedField(sb, field);
                    }
                }

                sb.Append('}');

                return (null, ServerHttpResponse.Ok(sb.ToString(), "application/json"));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    //Helpers go below the public surface.

    /// <summary>
    /// Appends a single discovery-document field whose value is an absolute
    /// endpoint URL, asking the application's
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// for the URL keyed by <paramref name="metadataKey"/>. No-op when the
    /// registration does not have <paramref name="capability"/> allowed or
    /// when the application returns <see langword="null"/> for the URL.
    /// </summary>
    /// <remarks>
    /// Part of the hand-written JSON-construction surface for the discovery
    /// document; see the serialization-firewall paragraph in the remarks on
    /// <see cref="MetadataEndpoints"/> for the rationale.
    /// </remarks>
    /// <param name="sb">The <see cref="StringBuilder"/> the field is written to.</param>
    /// <param name="server">The <see cref="AuthorizationServer"/> whose integration delegate composes the URL.</param>
    /// <param name="registration">The client registration whose capabilities gate field emission.</param>
    /// <param name="context">The per-request context bag the application's URL composer reads.</param>
    /// <param name="capability">The capability that must be allowed for this field to be emitted.</param>
    /// <param name="metadataKey">The discovery-document JSON property name and the endpoint-role key passed to <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private static async ValueTask AppendEndpointAsync(
        StringBuilder sb,
        AuthorizationServer server,
        ClientRegistration registration,
        RequestContext context,
        ServerCapabilityName capability,
        string metadataKey,
        CancellationToken cancellationToken)
    {
        if(!registration.IsCapabilityAllowed(capability))
        {
            return;
        }

        Uri? uri = await server.Integration.ResolveEndpointUriAsync!(
            metadataKey, registration, context, cancellationToken).ConfigureAwait(false);

        if(uri is null)
        {
            return;
        }

        AppendField(sb, metadataKey, uri.ToString());
    }


    /// <summary>
    /// Appends a single string-valued JSON field to the discovery-document
    /// builder, formatted as <c>,"key":"value"</c>. Always emits the leading
    /// comma; callers must have written the opening brace and at least the
    /// <c>issuer</c> field before calling.
    /// </summary>
    /// <remarks>
    /// Part of the hand-written JSON-construction surface for the discovery
    /// document; see the serialization-firewall paragraph in the remarks on
    /// <see cref="MetadataEndpoints"/> for the rationale.
    /// </remarks>
    /// <param name="sb">The <see cref="StringBuilder"/> the field is written to.</param>
    /// <param name="key">The JSON property name.</param>
    /// <param name="value">The JSON property value, written as a JSON string.</param>
    private static void AppendField(StringBuilder sb, string key, string value)
    {
        sb.Append(",\"");
        sb.Append(key);
        sb.Append("\":\"");
        sb.Append(value);
        sb.Append('"');
    }


    /// <summary>
    /// Appends a single application-contributed discovery-document field to
    /// the builder, dispatching on the <see cref="DiscoveryField"/> record
    /// subtype: <see cref="DiscoveryStringField"/> emits as a JSON string,
    /// <see cref="DiscoveryBooleanField"/> as a JSON boolean,
    /// <see cref="DiscoveryNumberField"/> as a JSON integer formatted with
    /// invariant culture, and <see cref="DiscoveryStringArrayField"/> as a
    /// JSON array of strings. Always emits the leading comma; callers must
    /// have written the opening brace and at least the <c>issuer</c> field
    /// before calling.
    /// </summary>
    /// <remarks>
    /// Part of the hand-written JSON-construction surface for the discovery
    /// document; see the serialization-firewall paragraph in the remarks on
    /// <see cref="MetadataEndpoints"/> for the rationale. The application
    /// hands the library typed field instances via
    /// <see cref="AuthorizationServerIntegration.ContributeDiscoveryFieldsAsync"/>;
    /// the closed <see cref="DiscoveryField"/> hierarchy means the library
    /// knows the JSON shape of every value at compile time without any
    /// runtime CLR-type inspection.
    /// </remarks>
    /// <param name="sb">The <see cref="StringBuilder"/> the field is written to.</param>
    /// <param name="field">The contributed field, dispatched on its record subtype.</param>
    private static void AppendContributedField(StringBuilder sb, DiscoveryField field)
    {
        sb.Append(",\"");
        sb.Append(field.Name);
        sb.Append("\":");

        switch(field)
        {
            case DiscoveryStringField stringField:
                sb.Append('"');
                sb.Append(stringField.Value);
                sb.Append('"');
                return;

            case DiscoveryBooleanField booleanField:
                sb.Append(booleanField.Value ? "true" : "false");
                return;

            case DiscoveryNumberField numberField:
                sb.Append(numberField.Value.ToString(CultureInfo.InvariantCulture));
                return;

            case DiscoveryStringArrayField arrayField:
                sb.Append('[');
                bool firstItem = true;
                foreach(string item in arrayField.Values)
                {
                    if(!firstItem)
                    {
                        sb.Append(',');
                    }

                    firstItem = false;
                    sb.Append('"');
                    sb.Append(item);
                    sb.Append('"');
                }

                sb.Append(']');
                return;

            default:
                //Library invariant: the DiscoveryField hierarchy is closed
                //and exhaustively handled above. A new subtype added without
                //updating this dispatch is a library bug.
                throw new InvalidOperationException(
                    $"Unhandled discovery field record subtype '{field.GetType().FullName}'.");
        }
    }


    /// <summary>
    /// Serializes a <see cref="JwksDocument"/> to its
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5">RFC 7517 §5</see>
    /// JSON wire form: <c>{"keys":[{...},{...}]}</c>. Each
    /// <see cref="JsonWebKey"/>'s entries are emitted in iteration order via
    /// <see cref="AppendJsonValue"/>; no field-name precedence or omission
    /// rules are applied here, the document is taken as-is.
    /// </summary>
    /// <remarks>
    /// Part of the hand-written JSON-construction surface for the JWKS
    /// endpoint; see the serialization-firewall paragraph in the remarks on
    /// <see cref="MetadataEndpoints"/> for the rationale.
    /// </remarks>
    /// <param name="jwks">The JWKS document to serialize.</param>
    /// <returns>The JSON wire form as a UTF-16 string suitable for an HTTP response body.</returns>
    private static string BuildJwksJson(JwksDocument jwks)
    {
        var sb = new StringBuilder();
        sb.Append("{\"keys\":[");

        bool first = true;
        foreach(JsonWebKey key in jwks.Keys)
        {
            if(!first)
            {
                sb.Append(',');
            }

            first = false;
            sb.Append('{');

            bool firstProp = true;
            foreach(KeyValuePair<string, object> entry in key)
            {
                AppendJsonValue(sb, entry.Key, entry.Value, ref firstProp);
            }

            sb.Append('}');
        }

        sb.Append("]}");
        return sb.ToString();
    }


    /// <summary>
    /// Appends a single JWK property to the builder, dispatching on the
    /// runtime CLR type of <paramref name="value"/>: <see cref="string"/>
    /// emits as a JSON string, <see cref="bool"/> as a JSON boolean,
    /// <see cref="IReadOnlyList{T}"/> of <see cref="string"/> as a JSON
    /// array of strings, <see cref="IFormattable"/> as the
    /// invariant-culture string form, and any other value via
    /// <see cref="object.ToString"/> wrapped as a JSON string. The leading
    /// comma is emitted on every call after the first within the same
    /// JWK-object scope, tracked via the
    /// <paramref name="firstProp"/> ref parameter.
    /// </summary>
    /// <remarks>
    /// Part of the hand-written JSON-construction surface for the JWKS
    /// endpoint; see the serialization-firewall paragraph in the remarks on
    /// <see cref="MetadataEndpoints"/> for the rationale.
    /// </remarks>
    /// <param name="sb">The <see cref="StringBuilder"/> the property is written to.</param>
    /// <param name="name">The JSON property name.</param>
    /// <param name="value">The property value, dispatched on its runtime CLR type.</param>
    /// <param name="firstProp">Tracks whether this is the first property in the enclosing JWK object; set to <see langword="false"/> after the first call. Pass <see langword="true"/> initially per JWK.</param>
    private static void AppendJsonValue(
        StringBuilder sb,
        string name,
        object value,
        ref bool firstProp)
    {
        if(!firstProp)
        {
            sb.Append(',');
        }

        firstProp = false;
        sb.Append('"');
        sb.Append(name);
        sb.Append("\":");

        if(value is string s)
        {
            sb.Append('"');
            sb.Append(s);
            sb.Append('"');
            return;
        }

        if(value is bool b)
        {
            sb.Append(b ? "true" : "false");
            return;
        }

        if(value is IReadOnlyList<string> list)
        {
            sb.Append('[');
            bool firstItem = true;
            foreach(string item in list)
            {
                if(!firstItem)
                {
                    sb.Append(',');
                }

                firstItem = false;
                sb.Append('"');
                sb.Append(item);
                sb.Append('"');
            }

            sb.Append(']');
            return;
        }

        if(value is IFormattable formattable)
        {
            sb.Append(formattable.ToString(null, CultureInfo.InvariantCulture));
            return;
        }

        sb.Append('"');
        sb.Append(value.ToString());
        sb.Append('"');
    }
}
