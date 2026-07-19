using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.Server;

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
/// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/> chain. The skin invokes
/// <see cref="HandleCreateAsync"/> directly from its routing layer. RFC 7592 §2
/// (GET / PUT / DELETE on <c>/connect/{segment}/register</c>) is per-registration
/// and is registered via the <see cref="Builder"/> delegate that slots into
/// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
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
    /// management endpoints (GET / PUT / DELETE on the URL the application's
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// returns for <see cref="WellKnownEndpointNames.RegistrationRegister"/>).
    /// Pass this to <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    /// <remarks>
    /// Endpoints are emitted only when the registration's capability set
    /// includes <see cref="WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration"/>.
    /// </remarks>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        if(!((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration))
        {
            return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>([]);
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(
            [BuildRead(), BuildUpdate(), BuildDelete()]);
    };


    /// <summary>
    /// Handles the global RFC 7591 §3 POST request. Invoked by the application
    /// skin from its routing layer when a request arrives at the deployment's
    /// global registration endpoint (typically <c>/connect/register</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The application skin produces a <see cref="ExchangeContext"/> with the
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
        ImmutableHashSet<CapabilityIdentifier> capabilities,
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestBody);
        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(server);

        var oauth = server.OAuth();

        if(oauth.ParseClientMetadataAsync is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "ParseClientMetadataAsync is not configured.");
        }

        ClientMetadata metadata;
        try
        {
            metadata = await oauth.ParseClientMetadataAsync(
                requestBody, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidClientMetadata,
                "Request body did not parse as a valid RFC 7591 client metadata document.");
        }

        string clientId = await oauth.GenerateIdentifierAsync!(
            WellKnownIdentifierPurposes.OAuthClientId, context, cancellationToken)
            .ConfigureAwait(false);
        string accessTokenValue = await oauth.GenerateIdentifierAsync!(
            WellKnownIdentifierPurposes.OAuthRegistrationAccessToken, context, cancellationToken)
            .ConfigureAwait(false);
        RegistrationAccessToken accessToken = new(accessTokenValue);

        ClientRecord record = BuildRecordFromMetadata(clientId, tenantId, capabilities, metadata);

        server.RegisterClient(record, accessToken, context);

        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        string body = BuildRegistrationResponseJson(
            clientId, accessToken, metadata, now, tenantId.Value);

        //OAuth 2.1 §3.2.3 — the response carries client_secret and
        //registration_access_token (RFC 7591 §3.2.1). Same Cache-Control
        //requirement as token-bearing responses.
        return ServerHttpResponse
            .Created(body, WellKnownMediaTypes.Application.Json)
            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
    }


    private static ClientRecord BuildRecordFromMetadata(
        string clientId,
        TenantId tenantId,
        ImmutableHashSet<CapabilityIdentifier> capabilities,
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
            AllowedAuthorizationDetailsTypes = ToAllowedAuthorizationDetailsTypes(metadata),
            TokenEndpointAuthMethod = metadata.TokenEndpointAuthMethod,
            ClientJwksUri = metadata.JwksUri,
            ClientJwks = metadata.Jwks,
            ClientName = metadata.ClientName,
            ClientUri = metadata.ClientUri,
            TokenLifetimes = FrozenDictionary<string, TimeSpan>.Empty,
            SigningKeys = FrozenDictionary<Verifiable.Cryptography.Context.KeyUsageContext, SigningKeySet>.Empty
        };
    }


    //RFC 9396 §10/§14.5: the client registration metadata authorization_details_types becomes the
    //per-client AllowedAuthorizationDetailsTypes allowlist. An omitted parameter (null) registers
    //no restriction, mirroring the §10 "MAY indicate" semantics — the client may then use any
    //authorization details type the AS supports.
    private static ImmutableHashSet<string>? ToAllowedAuthorizationDetailsTypes(ClientMetadata metadata) =>
        metadata.AuthorizationDetailsTypes is null
            ? null
            : [.. metadata.AuthorizationDetailsTypes];


    private static string BuildRegistrationResponseJson(
        string clientId,
        RegistrationAccessToken accessToken,
        ClientMetadata metadata,
        DateTimeOffset now,
        string tenantSegment)
    {
        //RFC 7591 §3.2.1 response. Field order matches the RFC §2 table.
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringField(sb, "client_id", clientId, ref first);
            JsonAppender.AppendInt64Field(sb, "client_id_issued_at",
                now.ToUnixTimeSeconds(), ref first);
            JsonAppender.AppendStringField(sb, "registration_access_token",
                accessToken.Value, ref first);
            JsonAppender.AppendStringField(sb, "registration_client_uri",
                $"/connect/{tenantSegment}/register", ref first);
            AppendMetadataFields(sb, metadata, ref first);
            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    private static void AppendMetadataFields(
        StringBuilder sb, ClientMetadata metadata, ref bool first)
    {
        if(metadata.ClientName is not null)
        {
            JsonAppender.AppendStringField(sb, "client_name", metadata.ClientName, ref first);
        }
        if(metadata.ClientUri is not null)
        {
            JsonAppender.AppendUriField(sb, "client_uri", metadata.ClientUri, ref first);
        }
        if(metadata.RedirectUris.Count > 0)
        {
            JsonAppender.AppendUriArrayField(sb, "redirect_uris",
                metadata.RedirectUris, ref first);
        }
        if(metadata.Scope is not null)
        {
            JsonAppender.AppendStringField(sb, "scope", metadata.Scope, ref first);
        }
        if(metadata.AuthorizationDetailsTypes is not null)
        {
            //RFC 9396 §10/§14.5: echo the registered authorization_details_types so the client
            //sees the allowlist the AS will enforce on its authorization details requests.
            JsonAppender.AppendStringArrayField(sb,
                AuthorizationDetailsParameterNames.AuthorizationDetailsTypes,
                metadata.AuthorizationDetailsTypes, ref first);
        }
        if(metadata.TokenEndpointAuthMethod is not null)
        {
            JsonAppender.AppendStringField(sb, "token_endpoint_auth_method",
                ClientAuthenticationMethodNames.GetName(metadata.TokenEndpointAuthMethod.Value),
                ref first);
        }
        if(metadata.JwksUri is not null)
        {
            JsonAppender.AppendUriField(sb, "jwks_uri", metadata.JwksUri, ref first);
        }
        //Additional fields (grant_types, response_types, jwks, application_type,
        //id_token_signed_response_alg, logout URIs) follow the same pattern.
        //Implementations needing them add them here in the order the RFC §2 table lists.
    }


    private static EndpointCandidate BuildRead() => BuildManagementEndpoint(
        httpMethod: WellKnownHttpMethods.Get,
        handler: HandleReadAsync);


    private static EndpointCandidate BuildUpdate() => BuildManagementEndpoint(
        httpMethod: WellKnownHttpMethods.Put,
        handler: HandleUpdateAsync);


    private static EndpointCandidate BuildDelete() => BuildManagementEndpoint(
        httpMethod: WellKnownHttpMethods.Delete,
        handler: HandleDeleteAsync);


    private static EndpointCandidate BuildManagementEndpoint(
        string httpMethod,
        ManagementHandlerDelegate handler) =>
        new()
        {
            //RFC 7592 management endpoints (GET/PUT/DELETE) share a single role
            //identifier — they answer at the same URL distinguished only by
            //method. The discovery document advertises the create endpoint
            //(handled outside the chain in HandleCreateAsync), so these three
            //carry DiscoveryMetadataKey=null.
            Name = WellKnownEndpointNames.RegistrationRegister,
            HttpMethod = httpMethod,
            Capability = WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            //Acceptance test: the management endpoints all share the same URL
            //distinguished only by HTTP method; each chain entry's endpoint
            //carries its own HttpMethod so a single Read/Update/Delete entry
            //only accepts its own verb.
            MatchesRequest = (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.Equals(req.Method, httpMethod))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();
                ServerHttpResponse response = await handler(context, server, ct).ConfigureAwait(false);
                return ((FlowInput?)null, (ServerHttpResponse?)response);
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    "RegistrationEndpoints are stateless; BuildResponse must never be reached.")
        };


    private delegate ValueTask<ServerHttpResponse> ManagementHandlerDelegate(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken);


    private static async ValueTask<ServerHttpResponse> HandleReadAsync(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        ServerHttpResponse? authFailure = await ValidateBearerAsync(
            context, server, cancellationToken).ConfigureAwait(false);
        if(authFailure is not null) { return authFailure; }


        ClientRecord registration = context.ClientRegistration!;
        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        string body = BuildReadResponseJson(registration, now);
        //OAuth 2.1 §3.2.3 — the RFC 7592 read response echoes client
        //metadata that may include sensitive fields (registration access
        //token is omitted on read per RFC 7592 §3, but the response shape
        //is treated uniformly with create/update).
        return ServerHttpResponse
            .Ok(body, WellKnownMediaTypes.Application.Json)
            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
    }


    private static async ValueTask<ServerHttpResponse> HandleUpdateAsync(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        ServerHttpResponse? authFailure = await ValidateBearerAsync(
            context, server, cancellationToken).ConfigureAwait(false);
        if(authFailure is not null) { return authFailure; }

        if(oauth.ParseClientMetadataAsync is null)
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
            newMetadata = await oauth.ParseClientMetadataAsync(
                bodyText, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception)
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidClientMetadata,
                "Request body did not parse as a valid RFC 7591 client metadata document.");
        }

        ClientRecord previous = context.ClientRegistration!;
        ClientRecord updated = BuildUpdatedRecord(previous, newMetadata);

        server.UpdateClient(previous, updated, context);

        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        string responseBody = BuildReadResponseJson(updated, now);
        //OAuth 2.1 §3.2.3 — the update echoes the (possibly new)
        //credentials back to the caller; treat as a token-bearing response.
        return ServerHttpResponse
            .Ok(responseBody, WellKnownMediaTypes.Application.Json)
            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
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
            AllowedScopes = scopes,
            AllowedAuthorizationDetailsTypes = newMetadata.AuthorizationDetailsTypes is null
                ? previous.AllowedAuthorizationDetailsTypes
                : ToAllowedAuthorizationDetailsTypes(newMetadata),
            TokenEndpointAuthMethod = newMetadata.TokenEndpointAuthMethod,
            ClientJwksUri = newMetadata.JwksUri,
            ClientJwks = newMetadata.Jwks,
            ClientName = newMetadata.ClientName,
            ClientUri = newMetadata.ClientUri
        };
    }


    private static async ValueTask<ServerHttpResponse> HandleDeleteAsync(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        ServerHttpResponse? authFailure = await ValidateBearerAsync(
            context, server, cancellationToken).ConfigureAwait(false);
        if(authFailure is not null) { return authFailure; }

        ClientRecord registration = context.ClientRegistration!;
        server.DeregisterClient(registration, "RFC 7592 DELETE", context);

        return ServerHttpResponse.NoContent();
    }


    private static async ValueTask<ServerHttpResponse?> ValidateBearerAsync(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(oauth.ValidateRegistrationAccessTokenAsync is null)
        {
            return ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "ValidateRegistrationAccessTokenAsync is not configured.");
        }

        IncomingRequest? req = context.IncomingRequest;
        string bearerPrefix = WellKnownAuthenticationSchemes.Bearer + " ";
        if(req is null
            || !req.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authHeader)
            || authHeader is null
            || !authHeader.StartsWith(bearerPrefix, StringComparison.Ordinal))
        {
            return ServerHttpResponse.Unauthorized(
                OAuthErrors.InvalidToken,
                "Missing or malformed Authorization header.");
        }

        string presented = authHeader[bearerPrefix.Length..];
        ClientRecord registration = context.ClientRegistration!;

        bool valid = await oauth.ValidateRegistrationAccessTokenAsync(
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
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringField(sb, "client_id", registration.ClientId, ref first);
            JsonAppender.AppendUriArrayField(sb, "redirect_uris",
                registration.AllowedRedirectUris, ref first);
            if(registration.AllowedScopes.Count > 0)
            {
                //RFC 6749 §3.3 says scope order does not matter on the wire, so the
                //internal store is an ImmutableHashSet (correct set semantics for
                //membership checks). Sort alphabetically on output so the response
                //body is byte-for-byte deterministic across invocations — easier
                //debugging, stable diffs in audit logs.
                string scope = string.Join(' ',
                    registration.AllowedScopes.OrderBy(s => s, StringComparer.Ordinal));
                JsonAppender.AppendStringField(sb, "scope", scope, ref first);
            }
            if(registration.AllowedAuthorizationDetailsTypes is not null)
            {
                //RFC 9396 §10/§14.5: echo the registered authorization_details_types allowlist.
                //Sort ordinally so the body is byte-for-byte deterministic, matching the scope
                //field's treatment (the internal store is an unordered ImmutableHashSet).
                JsonAppender.AppendStringArrayField(sb,
                    AuthorizationDetailsParameterNames.AuthorizationDetailsTypes,
                    registration.AllowedAuthorizationDetailsTypes.OrderBy(t => t, StringComparer.Ordinal),
                    ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
