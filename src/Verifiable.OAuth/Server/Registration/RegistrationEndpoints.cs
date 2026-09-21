using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Client;

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
/// Successful registrations commit through <see cref="IClientRegistrationStore"/> before
/// optional observers receive an immutable projection. Only the required store and the
/// client response receive the management credential. The library
/// validates RFC 7592 bearer tokens via
/// <see cref="AuthorizationServerIntegration.ValidateRegistrationAccessTokenAsync"/>
/// — the application's delegate answers true/false against its stored form.
/// </para>
/// <para>
/// <strong>Serialization firewall.</strong> Response bodies are hand-written
/// via <see cref="StringBuilder"/> following the precedent set by
/// <see cref="Metadata.MetadataEndpoints"/>: <c>Verifiable.OAuth</c> must not
/// reference <c>System.Text.Json</c>. Request body parsing goes through
/// <see cref="AuthorizationServerIntegration.ParseClientMetadataAsync"/>,
/// for which no default implementation is shipped — the application
/// supplies its own JSON layer (see
/// <see cref="ParseClientMetadataServerDelegate"/>).
/// </para>
/// </remarks>
public static class RegistrationEndpoints
{
    /// <summary>
    /// The endpoint builder delegate for the per-registration RFC 7592
    /// management endpoints (GET / PUT / DELETE on the URL the application's
    /// <see cref="Verifiable.Server.ServerIntegration.ResolveEndpointUriAsync"/>
    /// returns for <see cref="WellKnownEndpointNames.RegistrationRegister"/>).
    /// Pass this to <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    /// <remarks>
    /// Endpoints are emitted only when the registration's capability set
    /// includes <see cref="WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration"/>.
    /// </remarks>
    public static EndpointBuilderDelegate Builder { get; } = static (registration, context, ct) =>
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
    /// <see cref="ClientRecord"/>, commits it through the required registration store,
    /// emits <see cref="ClientRegistered"/> to optional observers, and returns the
    /// RFC 7591 §3.2.1 response body.
    /// </para>
    /// <para>
    /// The handler does NOT load any prior registration — by definition there
    /// is none. It does NOT validate any bearer — the global endpoint is
    /// unauthenticated per RFC 7591 §2 (initial registration trust is
    /// out-of-band; deployments needing initial-trust gating handle that at
    /// the skin layer).
    /// </para>
    /// <para>Acquires the same validated admission lease as dispatch. A bounded admission wait can return
    /// HTTP 503 with Retry-After; never-validated wiring throws a named InvalidOperationException.</para>
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

        using ServerRequestLease? lease = await server.AcquireRequestAsync(context, cancellationToken).ConfigureAwait(false);
        if(lease is null)
        {

            return EndpointServer.AdmissionRefusal;
        }

        server = lease.Server;
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
            //oauth.ParseClientMetadataAsync is a caller-registered delegate over an untrusted request body;
            //any parse failure is a bad request rather than an internal fault.

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
        Uri? managementUri = await oauth.ResolveEndpointUriAsync!(WellKnownEndpointNames.RegistrationRegister,
            record, context, cancellationToken).ConfigureAwait(false);
        if(managementUri is null || !managementUri.IsAbsoluteUri)
        {
            throw new InvalidOperationException("Registration requires an absolute client configuration URI.");
        }

        record = record with { RegistrationClientUri = managementUri };

        IClientRegistrationStore store = oauth.ClientRegistrationStore
            ?? throw new InvalidOperationException("Registration requires ClientRegistrationStore.");
        await store.CreateAsync(record, accessToken, context, cancellationToken).ConfigureAwait(false);
        await server.RegisterClientAsync(record, context).ConfigureAwait(false);

        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        string body = BuildRegistrationResponseJson(
            clientId, accessToken, record.RegisteredMetadata!, now, managementUri);

        //OAuth 2.1 §3.2.3 — the response carries client_secret and
        //registration_access_token (RFC 7591 §3.2.1). Same Cache-Control
        //requirement as token-bearing responses.

        return ServerHttpResponse
            .Created(body, WellKnownMediaTypes.Application.Json)
            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
    }


    /// <summary>Selects the RFC 7591 client metadata fields persisted in a new revision-one record.</summary>
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
            RegisteredMetadata = CopyMetadata(metadata),
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


    /// <summary>Maps RFC 9396 §10 optional authorization detail types to the immutable allowlist.</summary>
    private static ImmutableHashSet<string>? ToAllowedAuthorizationDetailsTypes(ClientMetadata metadata) =>
        metadata.AuthorizationDetailsTypes is null
            ? null
            : [.. metadata.AuthorizationDetailsTypes];


    /// <summary>Builds the RFC 7591 §3.2.1 response, including the client-only management credential.</summary>
    private static string BuildRegistrationResponseJson(
        string clientId,
        RegistrationAccessToken accessToken,
        ClientMetadata metadata,
        DateTimeOffset now,
        Uri managementUri)
    {
        //RFC 7591 §3.2.1 response. Field order matches the RFC §2 table.
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            _ = sb.Append('{');
            bool isFirst = true;
            JsonAppender.AppendStringField(sb, ClientMetadataParameterNames.ClientId, clientId, ref isFirst);
            JsonAppender.AppendInt64Field(sb, ClientMetadataParameterNames.ClientIdIssuedAt,
                now.ToUnixTimeSeconds(), ref isFirst);
            JsonAppender.AppendStringField(sb, "registration_access_token",
                accessToken.Value, ref isFirst);
            JsonAppender.AppendStringField(sb, "registration_client_uri",
                managementUri.AbsoluteUri, ref isFirst);
            ClientMetadataJson.Append(sb, metadata, ref isFirst);
            _ = sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>Builds the RFC 7592 §2.1 authenticated read operation.</summary>
    private static EndpointCandidate BuildRead() => BuildManagementEndpoint(
        httpMethod: WellKnownHttpMethods.Get,
        handler: HandleReadAsync);


    /// <summary>Builds the RFC 7592 §2.2 authenticated conditional replacement operation.</summary>
    private static EndpointCandidate BuildUpdate() => BuildManagementEndpoint(
        httpMethod: WellKnownHttpMethods.Put,
        handler: HandleUpdateAsync);


    /// <summary>Builds the RFC 7592 §2.3 authenticated deletion operation.</summary>
    private static EndpointCandidate BuildDelete() => BuildManagementEndpoint(
        httpMethod: WellKnownHttpMethods.Delete,
        handler: HandleDeleteAsync);


    /// <summary>Builds a registration management endpoint using the request's admitted family wiring.</summary>
    /// <remarks><see href="https://www.rfc-editor.org/rfc/rfc7592#section-2">RFC 7592 §2</see> defines the authenticated client configuration operations.</remarks>
    /// <param name="httpMethod">The HTTP method selecting the configuration operation.</param>
    /// <param name="handler">The authenticated operation handler.</param>
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
                if(req is null)
                {

                    return ValueTask.FromResult<MatchPayload?>(null);
                }

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
                EndpointServer server = context.RequestServer!;
                ServerHttpResponse response = await handler(context, server, ct).ConfigureAwait(false);

                return (null, response);
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    "RegistrationEndpoints are stateless; BuildResponse must never be reached.")
        };


    /// <summary>The authenticated RFC 7592 operation selected by the management HTTP method.</summary>
    private delegate ValueTask<ServerHttpResponse> ManagementHandlerDelegate(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken);


    /// <summary>Returns the stored RFC 7592 §2.1 client metadata after bearer authentication.</summary>
    private static async ValueTask<ServerHttpResponse> HandleReadAsync(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        ServerHttpResponse? authFailure = await ValidateBearerAsync(
            context, server, cancellationToken).ConfigureAwait(false);
        if(authFailure is not null)
        {

            return authFailure;
        }


        ClientRecord registration = context.ClientRegistration!;
        string body = BuildReadResponseJson(registration, context);
        //The client-information response carries the authenticated management bearer.

        return ServerHttpResponse
            .Ok(body, WellKnownMediaTypes.Application.Json)
            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
    }


    /// <summary>Commits one conditional RFC 7592 §2.2 replacement before optional notification; a stale revision receives invalid_client_metadata.</summary>
    private static async ValueTask<ServerHttpResponse> HandleUpdateAsync(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        ServerHttpResponse? authFailure = await ValidateBearerAsync(
            context, server, cancellationToken).ConfigureAwait(false);
        if(authFailure is not null)
        {

            return authFailure;
        }

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
            //oauth.ParseClientMetadataAsync is a caller-registered delegate over an untrusted request body;
            //any parse failure is a bad request rather than an internal fault.

            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidClientMetadata,
                "Request body did not parse as a valid RFC 7591 client metadata document.");
        }

        ClientRecord previous = context.ClientRegistration!;
        if(!string.Equals(newMetadata.ClientId, previous.ClientId, StringComparison.Ordinal))
        {

            return ServerHttpResponse.BadRequest(OAuthErrors.InvalidClientMetadata,
                "RFC 7592 section 2.2 requires the issued client_id in the replacement document.");
        }

        ClientRecord updated = BuildUpdatedRecord(previous, newMetadata);

        IClientRegistrationStore store = oauth.ClientRegistrationStore
            ?? throw new InvalidOperationException("Registration requires ClientRegistrationStore.");
        bool isCommitted = await store.TryUpdateAsync(updated, previous.Revision, context, cancellationToken).ConfigureAwait(false);
        if(!isCommitted)
        {

            return ServerHttpResponse.BadRequest(OAuthErrors.InvalidClientMetadata,
                "The registration changed during this update.");
        }

        await server.UpdateClientAsync(previous, updated, context).ConfigureAwait(false);

        string responseBody = BuildReadResponseJson(updated, context);
        //OAuth 2.1 §3.2.3 — the update echoes the (possibly new)
        //credentials back to the caller; treat as a token-bearing response.

        return ServerHttpResponse
            .Ok(responseBody, WellKnownMediaTypes.Application.Json)
            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
    }


    /// <summary>Builds the next revision of the registered RFC 7592 §2.2 client metadata.</summary>
    private static ClientRecord BuildUpdatedRecord(ClientRecord previous, ClientMetadata newMetadata)
    {
        ImmutableHashSet<Uri> redirectUris = [.. newMetadata.RedirectUris];
        ImmutableHashSet<string> scopes = newMetadata.Scope is null
            ? []
            : [.. newMetadata.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)];

        return previous with
        {
            Revision = checked(previous.Revision + 1),
            RegisteredMetadata = CopyMetadata(newMetadata),
            AllowedRedirectUris = redirectUris,
            AllowedScopes = scopes,
            AllowedAuthorizationDetailsTypes = ToAllowedAuthorizationDetailsTypes(newMetadata),
            TokenEndpointAuthMethod = newMetadata.TokenEndpointAuthMethod,
            ClientJwksUri = newMetadata.JwksUri,
            ClientJwks = newMetadata.Jwks,
            ClientName = newMetadata.ClientName,
            ClientUri = newMetadata.ClientUri
        };
    }


    /// <summary>Commits RFC 7592 §2.3 deletion before notifying optional observers.</summary>
    private static async ValueTask<ServerHttpResponse> HandleDeleteAsync(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        ServerHttpResponse? authFailure = await ValidateBearerAsync(
            context, server, cancellationToken).ConfigureAwait(false);
        if(authFailure is not null)
        {

            return authFailure;
        }

        ClientRecord registration = context.ClientRegistration!;
        IClientRegistrationStore store = server.OAuth().ClientRegistrationStore
            ?? throw new InvalidOperationException("Registration requires ClientRegistrationStore.");
        while(true)
        {
            ClientRecord? deleted = await store.DeleteAsync(registration, registration.Revision, context, cancellationToken).ConfigureAwait(false);
            if(deleted is not null)
            {
                await server.DeregisterClientAsync(deleted, "RFC 7592 DELETE", context).ConfigureAwait(false);
                break;
            }

            cancellationToken.ThrowIfCancellationRequested();
            ClientRecord? current = await server.Integration.LoadRegistrationAsync!(registration.TenantId,
                context, cancellationToken).ConfigureAwait(false) as ClientRecord;
            if(current is null || !string.Equals(current.ClientId, registration.ClientId, StringComparison.Ordinal))
            {

                return ServerHttpResponse.Unauthorized(OAuthErrors.InvalidToken, "Registration access token is invalid.");
            }

            registration = current;
        }

        return ServerHttpResponse.NoContent();
    }


    /// <summary>Checks the RFC 7592 §2 management bearer against the required stored credential.</summary>
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

        bool isValid = await oauth.ValidateRegistrationAccessTokenAsync(
            registration.TenantId,
            registration.ClientId,
            presented,
            context,
            cancellationToken).ConfigureAwait(false);

        if(!isValid)
        {

            return ServerHttpResponse.Unauthorized(
                OAuthErrors.InvalidToken,
                "Registration access token is invalid.");
        }

        return null;
    }


    /// <summary>Builds the complete RFC 7592 section 3 response, echoing the validated bearer and all accepted metadata.</summary>
    private static string BuildReadResponseJson(ClientRecord registration, ExchangeContext context)
    {
        _ = context.IncomingRequest!.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authorization);
        string bearer = authorization![(WellKnownAuthenticationSchemes.Bearer.Length + 1)..];
        Uri managementUri = registration.RegistrationClientUri
            ?? throw new InvalidOperationException("The registration has no client configuration URI.");
        ClientMetadata metadata = (registration.RegisteredMetadata ?? new ClientMetadata()) with
        {
            ClientName = registration.ClientName,
            ClientUri = registration.ClientUri,
            RedirectUris = registration.AllowedRedirectUris.OrderBy(uri => uri.AbsoluteUri, StringComparer.Ordinal).ToImmutableArray(),
            Scope = registration.AllowedScopes.Count == 0 ? null : string.Join(' ', registration.AllowedScopes.Order(StringComparer.Ordinal)),
            AuthorizationDetailsTypes = registration.AllowedAuthorizationDetailsTypes?.Order(StringComparer.Ordinal).ToImmutableArray(),
            TokenEndpointAuthMethod = registration.TokenEndpointAuthMethod,
            JwksUri = registration.ClientJwksUri,
            Jwks = registration.ClientJwks
        };
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            _ = sb.Append('{');
            bool isFirst = true;
            JsonAppender.AppendStringField(sb, ClientMetadataParameterNames.ClientId, registration.ClientId, ref isFirst);
            JsonAppender.AppendStringField(sb, "registration_access_token", bearer, ref isFirst);
            JsonAppender.AppendStringField(sb, "registration_client_uri", managementUri.AbsoluteUri, ref isFirst);
            ClientMetadataJson.Append(sb, metadata, ref isFirst);
            _ = sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>Copies every metadata collection before the required store can retain a parsed document.</summary>
    private static ClientMetadata CopyMetadata(ClientMetadata metadata) => metadata with
    {
        RedirectUris = metadata.RedirectUris.ToImmutableArray(),
        GrantTypes = metadata.GrantTypes.ToImmutableArray(),
        ResponseTypes = metadata.ResponseTypes.ToImmutableArray(),
        AuthorizationDetailsTypes = metadata.AuthorizationDetailsTypes?.ToImmutableArray(),
        AuthorizationGrantProfilesSupported = metadata.AuthorizationGrantProfilesSupported?.ToImmutableArray(),
        PostLogoutRedirectUris = metadata.PostLogoutRedirectUris.ToImmutableArray()
    };
}
