using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server.Routing;

namespace Verifiable.OAuth.Server.Registration;

/// <summary>
/// Endpoint builder and global-create handler for
/// <see href="https://www.rfc-editor.org/rfc/rfc7591">RFC 7591</see> dynamic
/// client registration and
/// <see href="https://www.rfc-editor.org/rfc/rfc7592">RFC 7592</see>
/// registration management.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Two entry points.</strong> RFC 7591 §3 (POST <c>/connect/register</c>)
/// is global — there is no registration yet, so it cannot fit the per-registration
/// <see cref="ServerConfiguration.EndpointBuilders"/> chain. The skin invokes
/// <see cref="HandleCreateAsync"/> directly from its routing layer. RFC 7592 §2
/// (GET / PUT / DELETE on <c>/connect/{segment}/register</c>) is per-registration
/// and is registered via the <see cref="Builder"/> delegate that slots into
/// <see cref="ServerConfiguration.EndpointBuilders"/>.
/// </para>
/// <para>
/// <strong>Storage model.</strong> The library does not own credential storage.
/// Successful registrations emit <see cref="ClientRegistered"/> events carrying
/// the plaintext access token; the application's event observer persists the
/// record alongside whatever hashed form of the token it chooses. The library
/// validates RFC 7592 bearer tokens via
/// <see cref="AuthorizationServerIntegration.ValidateRegistrationAccessTokenAsync"/>
/// — the application's delegate answers true/false against its stored form.
/// </para>
/// <para>
/// <strong>Serialization firewall.</strong> Response bodies are hand-written
/// via <see cref="StringBuilder"/> following the precedent set by
/// <see cref="Metadata.MetadataEndpoints"/>: <c>Verifiable.OAuth</c> must not
/// reference <c>System.Text.Json</c>. Request body parsing goes through
/// <see cref="AuthorizationServerIntegration.ParseClientMetadataAsync"/>; the
/// application's wiring (typically from <c>Verifiable.OAuth.Json</c>) supplies
/// the JSON layer.
/// </para>
/// </remarks>
[DebuggerDisplay("RegistrationEndpoints")]
[SuppressMessage("Reliability", "CA2007:Consider calling ConfigureAwait on the awaited task", Justification = "Library code does not pin a SynchronizationContext; this static class is consumed by application code that controls the context.")]
public static class RegistrationEndpoints
{
    /// <summary>
    /// The endpoint builder delegate for the per-registration RFC 7592
    /// management endpoints (GET / PUT / DELETE on
    /// <see cref="ServerEndpointPaths.RegistrationManagement"/>). Pass this
    /// to <see cref="ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    /// <remarks>
    /// Endpoints are emitted only when the registration's capability set
    /// includes <see cref="ServerCapabilityName.DynamicClientRegistration"/>.
    /// </remarks>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, server) =>
    {
        if(!registration.IsCapabilityAllowed(ServerCapabilityName.DynamicClientRegistration))
        {
            return [];
        }

        return [BuildRead(), BuildUpdate(), BuildDelete()];
    };


    /// <summary>
    /// Handles the global RFC 7591 §3 POST request. Invoked by the application
    /// skin from its routing layer when a request arrives at
    /// <see cref="ServerEndpointPaths.GlobalRegistration"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The application skin produces a <see cref="RequestContext"/> with the
    /// resolved tenant identifier, then calls this method passing the request
    /// body as a string. The handler parses the body via
    /// <see cref="AuthorizationServerIntegration.ParseClientMetadataAsync"/>,
    /// generates a <c>client_id</c> and registration access token via the
    /// configured delegates (or library defaults), constructs the new
    /// <see cref="ClientRecord"/>, emits the
    /// <see cref="ClientRegistered"/> event for the application observer to
    /// persist, and returns the RFC 7591 §3.2.1 response body.
    /// </para>
    /// <para>
    /// The handler does NOT load any prior registration — by definition there
    /// is none. It does NOT validate any bearer — the global endpoint is
    /// unauthenticated per RFC 7591 §2 (initial registration trust is
    /// out-of-band; deployments needing initial-trust gating handle that at
    /// the skin layer).
    /// </para>
    /// </remarks>
    /// <param name="tenantId">The tenant the new registration belongs to.</param>
    /// <param name="requestBody">The JSON body of the registration request.</param>
    /// <param name="capabilities">The capability set the AS grants the new registration.</param>
    /// <param name="context">Request context carrying tracing and request-scoped state.</param>
    /// <param name="server">The authorization server instance.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The HTTP response — 201 on success with the registration body, or 400 on bad input.</returns>
    public static async ValueTask<ServerHttpResponse> HandleCreateAsync(
        TenantId tenantId,
        string requestBody,
        ImmutableHashSet<ServerCapabilityName> capabilities,
        RequestContext context,
        AuthorizationServer server,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestBody);
        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(server);

        AuthorizationServerIntegration integration = server.Integration;
        if(integration.ParseClientMetadataAsync is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "ParseClientMetadataAsync is not configured.");
        }

        ClientMetadata metadata;
        try
        {
            metadata = await integration.ParseClientMetadataAsync(
                requestBody, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidClientMetadata,
                "Request body did not parse as a valid RFC 7591 client metadata document.");
        }

        GenerateClientIdDelegate generateClientId =
            integration.GenerateClientIdAsync ?? DefaultGenerateClientIdAsync;
        GenerateRegistrationAccessTokenDelegate generateAccessToken =
            integration.GenerateRegistrationAccessTokenAsync ?? DefaultGenerateRegistrationAccessTokenAsync;

        string clientId = await generateClientId(context, cancellationToken).ConfigureAwait(false);
        RegistrationAccessToken accessToken = await generateAccessToken(context, cancellationToken).ConfigureAwait(false);

        ClientRecord record = BuildRecordFromMetadata(clientId, tenantId, capabilities, metadata);

        server.RegisterClient(record, accessToken, context);

        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        string body = BuildRegistrationResponseJson(
            clientId, accessToken, metadata, now, tenantId.Value);

        return ServerHttpResponse.Created(body, WellKnownMediaTypes.Application.Json);
    }


    /// <summary>
    /// The library's default <see cref="GenerateClientIdDelegate"/>. Emits
    /// <c>Guid.NewGuid().ToString("N")</c> — 32 hex characters from the
    /// CSPRNG-backed GUID v4 generator.
    /// </summary>
    public static ValueTask<string> DefaultGenerateClientIdAsync(
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Guid.NewGuid().ToString("N"));
    }


    /// <summary>
    /// The library's default <see cref="GenerateRegistrationAccessTokenDelegate"/>.
    /// Emits <c>Guid.NewGuid().ToString("N")</c> wrapped in
    /// <see cref="RegistrationAccessToken"/>.
    /// </summary>
    public static ValueTask<RegistrationAccessToken> DefaultGenerateRegistrationAccessTokenAsync(
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(new RegistrationAccessToken(Guid.NewGuid().ToString("N")));
    }


    private static ClientRecord BuildRecordFromMetadata(
        string clientId,
        TenantId tenantId,
        ImmutableHashSet<ServerCapabilityName> capabilities,
        ClientMetadata metadata)
    {
        ImmutableHashSet<Uri> redirectUris = [.. metadata.RedirectUris];
        ImmutableHashSet<string> scopes = metadata.Scope is null
            ? []
            : [.. metadata.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)];

        return new ClientRecord
        {
            ClientId = clientId,
            TenantId = tenantId,
            AllowedCapabilities = capabilities,
            AllowedRedirectUris = redirectUris,
            AllowedScopes = scopes,
            TokenLifetimes = FrozenDictionary<string, TimeSpan>.Empty,
            SigningKeys = FrozenDictionary<Verifiable.Cryptography.Context.KeyUsageContext, SigningKeySet>.Empty
        };
    }


    private static string BuildRegistrationResponseJson(
        string clientId,
        RegistrationAccessToken accessToken,
        ClientMetadata metadata,
        DateTimeOffset now,
        string tenantSegment)
    {
        //RFC 7591 §3.2.1 response. Hand-written to keep this assembly free
        //of System.Text.Json — see the serialization-firewall remarks on
        //the class doc comment.
        StringBuilder sb = new();
        sb.Append('{');
        AppendStringField(sb, "client_id", clientId, isFirst: true);
        AppendInt64Field(sb, "client_id_issued_at", now.ToUnixTimeSeconds(), isFirst: false);
        AppendStringField(sb, "registration_access_token", accessToken.Value, isFirst: false);
        AppendStringField(sb, "registration_client_uri",
            $"/connect/{tenantSegment}/register", isFirst: false);
        AppendMetadataFields(sb, metadata);
        sb.Append('}');
        return sb.ToString();
    }


    private static void AppendMetadataFields(StringBuilder sb, ClientMetadata metadata)
    {
        if(metadata.ClientName is not null)
        {
            AppendStringField(sb, "client_name", metadata.ClientName, isFirst: false);
        }
        if(metadata.ClientUri is not null)
        {
            AppendStringField(sb, "client_uri", metadata.ClientUri.OriginalString, isFirst: false);
        }
        if(metadata.RedirectUris.Count > 0)
        {
            AppendUriListField(sb, "redirect_uris", metadata.RedirectUris, isFirst: false);
        }
        if(metadata.Scope is not null)
        {
            AppendStringField(sb, "scope", metadata.Scope, isFirst: false);
        }
        if(metadata.TokenEndpointAuthMethod is not null)
        {
            AppendStringField(sb, "token_endpoint_auth_method",
                ClientAuthenticationMethodNames.GetName(metadata.TokenEndpointAuthMethod.Value),
                isFirst: false);
        }
        if(metadata.JwksUri is not null)
        {
            AppendStringField(sb, "jwks_uri", metadata.JwksUri.OriginalString, isFirst: false);
        }
        //Additional fields (grant_types, response_types, jwks, application_type,
        //id_token_signed_response_alg, logout URIs) follow the same pattern.
        //Implementations needing them add them here in the order the RFC §2 table lists.
    }


    private static void AppendStringField(StringBuilder sb, string key, string value, bool isFirst)
    {
        if(!isFirst) { sb.Append(','); }
        sb.Append('"').Append(key).Append("\":\"");
        AppendEscapedJsonString(sb, value);
        sb.Append('"');
    }


    private static void AppendInt64Field(StringBuilder sb, string key, long value, bool isFirst)
    {
        if(!isFirst) { sb.Append(','); }
        sb.Append('"').Append(key).Append("\":")
            .Append(value.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }


    private static void AppendUriListField(
        StringBuilder sb, string key, IReadOnlyList<Uri> values, bool isFirst)
    {
        if(!isFirst) { sb.Append(','); }
        sb.Append('"').Append(key).Append("\":[");
        for(int i = 0; i < values.Count; ++i)
        {
            if(i > 0) { sb.Append(','); }
            sb.Append('"');
            AppendEscapedJsonString(sb, values[i].OriginalString);
            sb.Append('"');
        }
        sb.Append(']');
    }


    private static void AppendEscapedJsonString(StringBuilder sb, string value)
    {
        for(int i = 0; i < value.Length; ++i)
        {
            char c = value[i];
            switch(c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if(c < 0x20)
                    {
                        sb.Append("\\u").Append(((int)c).ToString("x4",
                            System.Globalization.CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
    }


    private static ServerEndpoint BuildRead() => BuildManagementEndpoint(
        name: "Registration.Read",
        httpMethod: WellKnownHttpMethods.Get,
        handler: HandleReadAsync);


    private static ServerEndpoint BuildUpdate() => BuildManagementEndpoint(
        name: "Registration.Update",
        httpMethod: WellKnownHttpMethods.Put,
        handler: HandleUpdateAsync);


    private static ServerEndpoint BuildDelete() => BuildManagementEndpoint(
        name: "Registration.Delete",
        httpMethod: WellKnownHttpMethods.Delete,
        handler: HandleDeleteAsync);


    private static ServerEndpoint BuildManagementEndpoint(
        string name,
        string httpMethod,
        ManagementHandlerDelegate handler) =>
        new()
        {
            Name = name,
            HttpMethod = httpMethod,
            Capability = ServerCapabilityName.DynamicClientRegistration,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = (fields, context, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null)
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!WellKnownHttpMethods.Equals(req.Method, httpMethod))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                ClientRecord? registration = context.Registration;
                if(registration is null)
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!registration.IsCapabilityAllowed(ServerCapabilityName.DynamicClientRegistration))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!ServerPaths.IsEndpoint(req.Path,
                    ServerEndpointPaths.RegistrationManagement, registration.TenantId.Value))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = async (fields, context, currentState, server, ct) =>
            {
                ServerHttpResponse response = await handler(context, server, ct).ConfigureAwait(false);
                return ((OAuthFlowInput?)null, (ServerHttpResponse?)response);
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    "RegistrationEndpoints are stateless; BuildResponse must never be reached.")
        };


    private delegate ValueTask<ServerHttpResponse> ManagementHandlerDelegate(
        RequestContext context,
        AuthorizationServer server,
        CancellationToken cancellationToken);


    private static async ValueTask<ServerHttpResponse> HandleReadAsync(
        RequestContext context,
        AuthorizationServer server,
        CancellationToken cancellationToken)
    {
        ServerHttpResponse? authFailure = await ValidateBearerAsync(
            context, server, cancellationToken).ConfigureAwait(false);
        if(authFailure is not null) { return authFailure; }

        ClientRecord registration = context.Registration!;
        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        string body = BuildReadResponseJson(registration, now);
        return ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json);
    }


    private static async ValueTask<ServerHttpResponse> HandleUpdateAsync(
        RequestContext context,
        AuthorizationServer server,
        CancellationToken cancellationToken)
    {
        ServerHttpResponse? authFailure = await ValidateBearerAsync(
            context, server, cancellationToken).ConfigureAwait(false);
        if(authFailure is not null) { return authFailure; }

        AuthorizationServerIntegration integration = server.Integration;
        if(integration.ParseClientMetadataAsync is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "ParseClientMetadataAsync is not configured.");
        }

        RequestBody body = context.IncomingRequest?.Body ?? RequestBody.None;
        if(body.IsEmpty)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidClientMetadata,
                "RFC 7592 §2.2 PUT requires a request body.");
        }
        if(!WellKnownMediaTypes.Application.IsJson(body.ContentType))
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidClientMetadata,
                $"RFC 7592 §2.2 PUT requires Content-Type application/json; got '{body.ContentType}'.");
        }

        string bodyText = Encoding.UTF8.GetString(body.Bytes.Span);
        ClientMetadata newMetadata;
        try
        {
            newMetadata = await integration.ParseClientMetadataAsync(
                bodyText, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidClientMetadata,
                "Request body did not parse as a valid RFC 7591 client metadata document.");
        }

        ClientRecord previous = context.Registration!;
        ClientRecord updated = BuildUpdatedRecord(previous, newMetadata);

        server.UpdateClient(previous, updated, context);

        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        string responseBody = BuildReadResponseJson(updated, now);
        return ServerHttpResponse.Ok(responseBody, WellKnownMediaTypes.Application.Json);
    }


    private static ClientRecord BuildUpdatedRecord(ClientRecord previous, ClientMetadata newMetadata)
    {
        ImmutableHashSet<Uri> redirectUris = [.. newMetadata.RedirectUris];
        ImmutableHashSet<string> scopes = newMetadata.Scope is null
            ? previous.AllowedScopes
            : [.. newMetadata.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)];

        return previous with
        {
            AllowedRedirectUris = redirectUris,
            AllowedScopes = scopes
        };
    }


    private static async ValueTask<ServerHttpResponse> HandleDeleteAsync(
        RequestContext context,
        AuthorizationServer server,
        CancellationToken cancellationToken)
    {
        ServerHttpResponse? authFailure = await ValidateBearerAsync(
            context, server, cancellationToken).ConfigureAwait(false);
        if(authFailure is not null) { return authFailure; }

        ClientRecord registration = context.Registration!;
        server.DeregisterClient(registration, "RFC 7592 DELETE", context);

        return ServerHttpResponse.NoContent();
    }


    private static async ValueTask<ServerHttpResponse?> ValidateBearerAsync(
        RequestContext context,
        AuthorizationServer server,
        CancellationToken cancellationToken)
    {
        AuthorizationServerIntegration integration = server.Integration;
        if(integration.ValidateRegistrationAccessTokenAsync is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "ValidateRegistrationAccessTokenAsync is not configured.");
        }

        IncomingRequest? req = context.IncomingRequest;
        if(req is null
            || !req.Headers.TryGetSingle("Authorization", out string? authHeader)
            || authHeader is null
            || !authHeader.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            return ServerHttpResponse.Unauthorized(
                OAuthErrors.InvalidToken,
                "Missing or malformed Authorization header.");
        }

        string presented = authHeader["Bearer ".Length..];
        ClientRecord registration = context.Registration!;

        bool valid = await integration.ValidateRegistrationAccessTokenAsync(
            registration.TenantId,
            registration.ClientId,
            presented,
            context,
            cancellationToken).ConfigureAwait(false);

        if(!valid)
        {
            return ServerHttpResponse.Unauthorized(
                OAuthErrors.InvalidToken,
                "Registration access token is invalid.");
        }

        return null;
    }


    private static string BuildReadResponseJson(ClientRecord registration, DateTimeOffset now)
    {
        _ = now;
        StringBuilder sb = new();
        sb.Append('{');
        AppendStringField(sb, "client_id", registration.ClientId, isFirst: true);
        AppendUriListField(sb, "redirect_uris", [.. registration.AllowedRedirectUris], isFirst: false);
        if(registration.AllowedScopes.Count > 0)
        {
            //RFC 6749 §3.3 says scope order does not matter on the wire, so the
            //internal store is an ImmutableHashSet (correct set semantics for
            //membership checks). Sort alphabetically on output so the response
            //body is byte-for-byte deterministic across invocations — easier
            //debugging, stable diffs in audit logs.
            string scope = string.Join(' ', registration.AllowedScopes.OrderBy(s => s, StringComparer.Ordinal));
            AppendStringField(sb, "scope", scope, isFirst: false);
        }
        sb.Append('}');
        return sb.ToString();
    }
}
