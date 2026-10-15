using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vci;

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
/// <para>
/// <strong>The registration as stored.</strong> The read, the update and the deletion act on the registration
/// as stored, loaded through <see cref="Verifiable.Server.ServerIntegration.LoadRegistrationAsync"/>, not on the
/// record an application's materialization answered for the request, and each checks the presented
/// registration access token through
/// <see cref="AuthorizationServerIntegration.ValidateRegistrationAccessTokenAsync"/> for that stored record's
/// tenant and client identifier: the read answers the metadata of the revision it loaded, the update replaces it
/// conditioned on that revision, and the deletion deletes it conditioned on that revision, each in one pass that loads
/// and checks once. A change another party commits between the load and the conditional write fails the write, and
/// the update and the deletion answer such a lost race 400 <c>invalid_client_metadata</c> and load nothing again; a
/// replacement or revocation of a registration access token is such a change only when the application commits it
/// as the registration's next revision (<see cref="IClientRegistrationStore"/>). A read, an update or a deletion
/// whose client does not exist when the operation loads it, or whose stored record names another client, is
/// answered 401 with <c>invalid_token</c> in the body and the challenge
/// <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>, as a refused token is.
/// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 Section 2.1</see>: "If the client
/// does not exist on this server, the server MUST respond with HTTP 401 Unauthorized and the registration access
/// token used to make this request SHOULD be immediately revoked."
/// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 Section 2.2</see>: "If the client
/// does not exist on this server, the server MUST respond with HTTP 401 Unauthorized, and the registration access
/// token used to make this request SHOULD be immediately revoked."
/// </para>
/// <para>
/// <strong>Refusals and their challenges.</strong> The client configuration endpoint is an OAuth 2.0
/// protected resource (<see href="https://www.rfc-editor.org/rfc/rfc7592#section-2">RFC 7592 Section 2</see>),
/// and the 401 answers of its read, update and delete operations carry one <c>Bearer</c> challenge whose
/// <c>realm</c> is the issuer the request is served under: a request whose <c>Authorization</c> field holds
/// no Bearer token is answered with an empty body and <c>Bearer realm="&lt;issuer&gt;"</c>, with no store
/// call; a registration access token the application's seam refuses, and a read, an update or a deletion whose
/// client is not stored when the operation loads it, are answered with <c>invalid_token</c> in the body and
/// <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>. The 400 for an <c>Authorization</c> field sent on
/// two lines carries the challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_request"</c>; the other 400 and
/// 500 answers carry no challenge; a registration that is not a <see cref="ClientRecord"/> when the endpoint runs is
/// answered 500 <c>server_error</c>. A management request whose client does not exist when it arrives meets no
/// registration and is answered by <see cref="AuthorizationServerIntegration.ResolveMissingRegistrationAsync"/>, 401
/// <c>invalid_token</c> without a challenge, also when it carries no credential; since a known client's refused
/// token is challenged and an absent client's is not, the answer tells a caller whether a <c>client_id</c>
/// exists. The challenged answers need the issuer resolvable: a client this endpoint registers
/// carries no issuer of its own, so the application's issuer resolver or the request's context names it.
/// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>: "The
/// server generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1) containing at
/// least one challenge applicable to the target resource."
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

        ServerHttpResponse? declarationRefusal = RefuseUnverifiableDpopDeclaration(oauth, metadata);
        if(declarationRefusal is not null)
        {

            return declarationRefusal;
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
            DpopBoundAccessTokens = metadata.DpopBoundAccessTokens is true,
            TokenLifetimes = FrozenDictionary<string, TimeSpan>.Empty,
            SigningKeys = FrozenDictionary<Verifiable.Cryptography.Context.KeyUsageContext, SigningKeySet>.Empty
        };
    }


    /// <summary>
    /// The fixed description of the refusal of a registration or an update declaring <c>dpop_bound_access_tokens</c>
    /// <see langword="true"/> at an authorization server that verifies no DPoP proof, naming the member
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2">RFC 7591 Section 3.2.2</see>:
    /// <c>error_description</c> "Human-readable ASCII text description of the error used for debugging").
    /// </summary>
    private static string DpopBoundAccessTokensUnverifiableDescription { get; } =
        "dpop_bound_access_tokens cannot be true at an authorization server that verifies no DPoP proof.";


    /// <summary>
    /// Refuses client metadata declaring <c>dpop_bound_access_tokens</c> <see langword="true"/> where the server
    /// verifies no DPoP proof (<see cref="DpopRequestReading.IsProofValidationWired"/>, the one notion of a wired proof
    /// validation the metadata composer and the token endpoint read): such a client's every token request would be
    /// refused, since <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5.2">RFC 9449 Section 5.2</see> says
    /// "If the value is true, the authorization server MUST reject token requests from the client that do not contain
    /// the DPoP header." and a token request carrying the header meets a server that cannot check it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">RFC 7591 Section 2</see>: "The authorization server
    /// MAY reject any requested client metadata values by replacing requested values with suitable defaults as
    /// described in Section 3.2.1 or by returning an error response as described in Section 3.2.2." The refusal is the
    /// Section 3.2.2 error response, 400 <c>invalid_client_metadata</c> with
    /// <see cref="DpopBoundAccessTokensUnverifiableDescription"/>.
    /// </summary>
    /// <param name="oauth">The integration admitted for the request.</param>
    /// <param name="metadata">The client metadata the request carries.</param>
    /// <returns>The refusal, or <see langword="null"/> when the declaration can be honoured or is absent.</returns>
    private static ServerHttpResponse? RefuseUnverifiableDpopDeclaration(AuthorizationServerIntegration oauth, ClientMetadata metadata) =>
        (metadata.DpopBoundAccessTokens is true, DpopRequestReading.IsProofValidationWired(oauth)) switch
        {
            (true, false) => ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidClientMetadata, DpopBoundAccessTokensUnverifiableDescription),
            _ => null
        };


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


    /// <summary>
    /// Answers the RFC 7592 Section 2.1 read with the client metadata of the registration as stored, the revision
    /// <see cref="AuthenticateStoredRegistrationAsync"/> loaded and whose tenant and client identifier it checked the
    /// presented registration access token for, not the record an application's materialization answered for the
    /// request.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-3">RFC 7592 Section 3</see>: "Additionally, the
    /// authorization server MUST return all registered metadata about this client, including any fields provisioned
    /// by the authorization server itself."
    /// </summary>
    /// <param name="context">The per-request context.</param>
    /// <param name="server">The authorization server serving the request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The refusal <see cref="AuthenticateStoredRegistrationAsync"/> answers, or 200 with the stored registration's
    /// RFC 7592 Section 3 response.
    /// </returns>
    private static async ValueTask<ServerHttpResponse> HandleReadAsync(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        (ServerHttpResponse? refusal, ClientRecord? registration, string? validatedBearer) =
            await AuthenticateStoredRegistrationAsync(context, server, cancellationToken).ConfigureAwait(false);
        if(refusal is not null)
        {

            return refusal;
        }

        string body = BuildReadResponseJson(registration!, validatedBearer!);
        //The client-information response carries the authenticated management bearer.

        return ServerHttpResponse
            .Ok(body, WellKnownMediaTypes.Application.Json)
            .WithHeader(WellKnownHttpHeaderNames.CacheControl, WellKnownCacheControlValues.NoStore);
    }


    /// <summary>
    /// Commits one conditional RFC 7592 Section 2.2 replacement before optional notification; a stale revision receives
    /// invalid_client_metadata. The next revision is built from the registration as stored, the revision
    /// <see cref="AuthenticateStoredRegistrationAsync"/> loaded and whose tenant and client identifier it checked the
    /// presented registration access token for, not from the record an application's materialization answered for
    /// the request: the update sets the RFC 7591 metadata members <see cref="BuildUpdatedRecord"/> sets and no other
    /// member of the stored record, the conditional replacement is against that revision, so a registration another
    /// party changes between the load and the replacement is not replaced, and the notification receives the stored
    /// record as the earlier one, so nothing a materialization changes is written to the store.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 Section 2.2</see>: "Valid values of
    /// client metadata fields in this request MUST replace, not augment, the values previously associated with this
    /// client."
    /// </summary>
    /// <param name="context">The per-request context.</param>
    /// <param name="server">The authorization server serving the request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The refusal <see cref="AuthenticateStoredRegistrationAsync"/> answers, 400 <c>invalid_client_metadata</c> for a
    /// body that is not a replacement document or a revision that changed between the load and the replacement, or
    /// 200 with the replaced registration's RFC 7592 Section 3 response.
    /// </returns>
    private static async ValueTask<ServerHttpResponse> HandleUpdateAsync(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        (ServerHttpResponse? refusal, ClientRecord? stored, string? validatedBearer) =
            await AuthenticateStoredRegistrationAsync(context, server, cancellationToken).ConfigureAwait(false);
        if(refusal is not null)
        {

            return refusal;
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

        ClientRecord previous = stored!;
        if(!string.Equals(newMetadata.ClientId, previous.ClientId, StringComparison.Ordinal))
        {

            return ServerHttpResponse.BadRequest(OAuthErrors.InvalidClientMetadata,
                "RFC 7592 section 2.2 requires the issued client_id in the replacement document.");
        }

        ServerHttpResponse? declarationRefusal = RefuseUnverifiableDpopDeclaration(oauth, newMetadata);
        if(declarationRefusal is not null)
        {

            return declarationRefusal;
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

        string responseBody = BuildReadResponseJson(updated, validatedBearer!);
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
            ClientUri = newMetadata.ClientUri,
            DpopBoundAccessTokens = newMetadata.DpopBoundAccessTokens is true
        };
    }


    /// <summary>
    /// Commits the RFC 7592 Section 2.3 deletion of the registration as stored before notifying optional observers, in
    /// one pass: it authenticates once through <see cref="AuthenticateStoredRegistrationAsync"/>, which loads the
    /// registration with its revision and checks the presented registration access token for its tenant and client
    /// identifier, and deletes it once, conditioned on that revision. A conditional deletion that removes nothing,
    /// because another party changed or removed the registration after the load, commits nothing and emits nothing,
    /// and is answered as the update's lost race is answered; the registration is not loaded, checked or deleted again.
    /// A client that sends the deletion again is authenticated against the record it then finds.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.3">RFC 7592 Section 2.3</see>: "This request is
    /// authenticated by the registration access token issued to the client."
    /// </summary>
    /// <param name="context">The per-request context.</param>
    /// <param name="server">The authorization server serving the request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The refusal <see cref="AuthenticateStoredRegistrationAsync"/> answers, 400 <c>invalid_client_metadata</c> with the
    /// description "The registration changed during this deletion." for a registration another party changed or removed
    /// after the load, or 204.
    /// </returns>
    private static async ValueTask<ServerHttpResponse> HandleDeleteAsync(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        (ServerHttpResponse? refusal, ClientRecord? stored, _) =
            await AuthenticateStoredRegistrationAsync(context, server, cancellationToken).ConfigureAwait(false);
        if(refusal is not null)
        {

            return refusal;
        }

        IClientRegistrationStore store = server.OAuth().ClientRegistrationStore
            ?? throw new InvalidOperationException("Registration requires ClientRegistrationStore.");
        ClientRecord? deleted = await store.DeleteAsync(stored!, stored!.Revision, context, cancellationToken).ConfigureAwait(false);
        if(deleted is null)
        {

            return ServerHttpResponse.BadRequest(OAuthErrors.InvalidClientMetadata,
                "The registration changed during this deletion.");
        }

        await server.DeregisterClientAsync(deleted, "RFC 7592 DELETE", context).ConfigureAwait(false);

        return ServerHttpResponse.NoContent();
    }


    /// <summary>
    /// Authenticates an RFC 7592 Section 2 management request against the registration as stored, in one order for
    /// the read, the update and the deletion, each of which calls it once. First the <c>Authorization</c> field is
    /// read: a request whose field holds no Bearer token, as
    /// <see cref="BearerTokenValidation.TryExtractBearer(ExchangeContext, out string?)"/> reads it, is answered 401
    /// with an empty body and the challenge <c>Bearer realm="&lt;issuer&gt;"</c>, and a field sent on two lines 400
    /// <c>invalid_request</c> with the challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_request"</c>, both
    /// with no store call. Then the registration as stored is loaded, with its revision, through
    /// <see cref="Verifiable.Server.ServerIntegration.LoadRegistrationAsync"/> by the tenant of the request's
    /// registration. Then the presented token is checked through
    /// <see cref="AuthorizationServerIntegration.ValidateRegistrationAccessTokenAsync"/> for that stored record's
    /// tenant and client identifier, and the record is answered for the operation to act on, whose replacement or
    /// deletion is conditioned on the loaded revision. A stored record that is gone,
    /// is not a <see cref="ClientRecord"/> or names another client than the request's registration, and a token the
    /// seam refuses, are each answered by <see cref="RefuseRegistrationAccessTokenAsync"/>: the client the presented
    /// token was issued to does not exist on this server, or the token is not valid. A registration that is not a
    /// <see cref="ClientRecord"/> when the endpoint runs (an application's materializer may replace the one the
    /// dispatcher sets) is answered 500 <c>server_error</c> with
    /// <see cref="WellKnownOAuthErrorDescriptions.ServerNotReady"/> and no challenge, before the field is read.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 Section 2.1</see>: "If the client does
    /// not exist on this server, the server MUST respond with HTTP 401 Unauthorized and the registration access token
    /// used to make this request SHOULD be immediately revoked."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 Section 2.2</see>: "If the client does
    /// not exist on this server, the server MUST respond with HTTP 401 Unauthorized, and the registration access token
    /// used to make this request SHOULD be immediately revoked."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>: "The 500
    /// (Internal Server Error) status code indicates that the server encountered an unexpected condition that
    /// prevented it from fulfilling the request."
    /// </summary>
    /// <param name="context">The per-request context.</param>
    /// <param name="server">The authorization server holding the load and validation seams.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The refusal, no record and no token; or no refusal, the registration as stored whose token was checked, and the
    /// Bearer token that authenticated the client, which the read and the update echo in their response without
    /// reading the field again.
    /// </returns>
    private static async ValueTask<(ServerHttpResponse? Refusal, ClientRecord? Stored, string? ValidatedBearer)> AuthenticateStoredRegistrationAsync(
        ExchangeContext context,
        EndpointServer server,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(oauth.ValidateRegistrationAccessTokenAsync is null)
        {

            return (ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "ValidateRegistrationAccessTokenAsync is not configured."), null, null);
        }

        //The dispatcher sets the registration before a candidate runs, but an application's materializer
        //may replace it with a record that is not a ClientRecord; the endpoint cannot serve the request
        //then, and the fault is the server's wiring, not the caller's, so it is read before the field.
        ClientRecord? registration = context.ClientRegistration;
        if(registration is null)
        {

            return (ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, WellKnownOAuthErrorDescriptions.ServerNotReady), null, null);
        }

        //RFC 7592 Section 2: "The client MUST use its registration access token in all calls to this
        //endpoint as an OAuth 2.0 Bearer Token [RFC6750]." A request whose Authorization field holds no
        //Bearer token (no field, an empty or white-space value, another scheme) lacks the authentication
        //information this endpoint reads and gets the challenge with no error code and an empty body.
        //RFC 6750 Section 3.1: "If the request lacks any authentication information (e.g., the client was
        //unaware that authentication is necessary or attempted using an unsupported authentication
        //method), the resource server SHOULD NOT include an error code or other error information."
        //Sent on two lines the field is no credential (RFC 9110 Section 11.6.2) and the request is refused
        //400 invalid_request with the Bearer challenge, the one scheme this endpoint reads.
        AuthorizationFieldReading authorization = BearerTokenValidation.ReadAuthorizationField(context);
        if(authorization.IsRepeated)
        {

            return (await CredentialEndpointDpopValidation.RefuseRepeatedAuthorizationAsync(
                server, registration, context, cancellationToken).ConfigureAwait(false), null, null);
        }

        if(!BearerTokenValidation.TryExtractBearer(authorization, out string? presented))
        {

            return (await CredentialEndpointDpopValidation.ChallengedAsync(
                ServerHttpResponse.Unauthorized(), error: null, server, registration, context, cancellationToken)
                .ConfigureAwait(false), null, null);
        }

        //The registration as stored is loaded with its revision before the token is checked, the token is checked for
        //that record's tenant and client identifier, and the operation's write is conditioned on the loaded revision,
        //so a change another party commits as the registration's next revision between the load and the write fails it.
        ClientRecord? stored = await server.Integration.LoadRegistrationAsync!(registration.TenantId,
            context, cancellationToken).ConfigureAwait(false) as ClientRecord;
        if(stored is null || !string.Equals(stored.ClientId, registration.ClientId, StringComparison.Ordinal))
        {

            return (await RefuseRegistrationAccessTokenAsync(
                server, registration, context, cancellationToken).ConfigureAwait(false), null, null);
        }

        bool isValid = await oauth.ValidateRegistrationAccessTokenAsync(
            stored.TenantId,
            stored.ClientId,
            presented!,
            context,
            cancellationToken).ConfigureAwait(false);

        if(!isValid)
        {

            return (await RefuseRegistrationAccessTokenAsync(
                server, registration, context, cancellationToken).ConfigureAwait(false), null, null);
        }

        return (null, stored, presented);
    }


    /// <summary>
    /// Answers a request whose registration access token authenticates no client, a token the application's
    /// seam refuses or one whose client does not exist on this server: 401 with the body's error
    /// <c>invalid_token</c> and the challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>,
    /// attached by <see cref="CredentialEndpointDpopValidation.ChallengedAsync"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 Section 2.1</see>: "If the
    /// registration access token used to make this request is not valid, the server MUST respond with an error as
    /// described in the OAuth Bearer Token Usage specification [RFC6750]."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "If the protected
    /// resource request included an access token and failed authentication, the resource server SHOULD include the
    /// "error" attribute to provide the client with the reason why the access request was declined."
    /// </summary>
    /// <param name="server">The authorization server whose issuer resolver names the realm.</param>
    /// <param name="registration">The client (tenant) the request was addressed to.</param>
    /// <param name="context">The per-request context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The 401 refusal with its challenge.</returns>
    private static ValueTask<ServerHttpResponse> RefuseRegistrationAccessTokenAsync(
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        CredentialEndpointDpopValidation.ChallengedAsync(
            ServerHttpResponse.Unauthorized(OAuthErrors.InvalidToken, "Registration access token is invalid."),
            OAuthErrors.InvalidToken, server, registration, context, cancellationToken);


    /// <summary>
    /// Builds the complete RFC 7592 section 3 response, echoing the bearer <see cref="AuthenticateStoredRegistrationAsync"/>
    /// validated for this request, handed over by the handler so the field is read once, and all accepted metadata.
    /// </summary>
    /// <param name="registration">The registration whose metadata the response carries.</param>
    /// <param name="bearer">The registration access token that authenticated the request.</param>
    /// <returns>The JSON response body.</returns>
    private static string BuildReadResponseJson(ClientRecord registration, string bearer)
    {
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
            Jwks = registration.ClientJwks,

            //RFC 7592 Section 3: "Additionally, the authorization server MUST return all registered metadata about this
            //client, including any fields provisioned by the authorization server itself.", beside RFC 7591 Section
            //3.2.1, whose response carries "all registered metadata about this client". The record's declaration is reported whenever the
            //client declared the member or the record holds true, as the other record-held members are; a member the
            //client omitted and the record leaves false stays omitted.
            DpopBoundAccessTokens = registration.DpopBoundAccessTokens switch
            {
                true => true,
                false => registration.RegisteredMetadata?.DpopBoundAccessTokens is null ? null : false
            }
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
