using System.Text;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server.Pipeline;
namespace Verifiable.OAuth.Server.Metadata;

/// <summary>
/// Endpoint builder module for JWKS and Discovery metadata endpoints.
/// </summary>
/// <remarks>
/// <para>
/// Register at startup via <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>:
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
/// <see cref="WellKnownCapabilityIdentifiers.OAuthJwksEndpoint"/> or
/// <see cref="WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint"/> capabilities.
/// </para>
/// <para>
/// The discovery endpoint composes URLs by asking the application via
/// <see cref="Verifiable.Server.ServerIntegration.ResolveEndpointUriAsync"/>. The
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
public static class MetadataEndpoints
{


    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static EndpointBuilderDelegate Builder { get; } = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthJwksEndpoint))
        {
            candidates.Add(BuildJwks());
        }

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint))
        {
            //RFC 8414 §3.1 permits the same authorization server metadata at
            //multiple well-known locations derived from the issuer identifier.
            //The library mounts the identical discovery document twice: as the
            //OIDC Discovery openid-configuration role and at the RFC 8414 §3
            //default oauth-authorization-server location. Both candidates share
            //BuildDiscovery so the served body is byte-identical per tenant; the
            //distinct role name lets the application resolve each location's URL.
            candidates.Add(BuildDiscovery(WellKnownEndpointNames.MetadataDiscovery));
            candidates.Add(BuildDiscovery(WellKnownEndpointNames.MetadataOAuthAuthorizationServer));
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
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
    private static EndpointCandidate BuildJwks() =>
        new()
        {
            Name = WellKnownEndpointNames.MetadataJwks,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            DiscoveryMetadataKey = AuthorizationServerMetadataParameterNames.JwksUri,

            //Acceptance test: GET to the JWKS URL for this registration. The
            //chain build guarantees registration is loaded and capability is
            //allowed before any matcher runs; path comparison goes against the
            //endpoint's per-request ResolvedUri.
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

            //The JWKS endpoint is stateless — it does not step the PDA. BuildInputAsync
            //builds the complete response and returns it as an early exit. BuildResponse
            //is never reached.
            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.RequestServer!;
                AuthorizationServerIntegration oauth = server.OAuth();

                if(oauth.Cryptography.BuildJwksDocumentAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        WellKnownOAuthErrorDescriptions.ServerNotReady));
                }

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                JwksDocument jwks = await oauth.Cryptography.BuildJwksDocumentAsync(
                    registration, context, ct).ConfigureAwait(false);

                string body = BuildJwksJson(jwks);

                return (null, ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds an OAuth/OIDC discovery endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414</see>
    /// and the OpenID Connect Discovery 1.0 profile that extends it. The
    /// <paramref name="roleName"/> selects which well-known mount this candidate
    /// answers — <see cref="WellKnownEndpointNames.MetadataDiscovery"/> for the
    /// appended OIDC <c>openid-configuration</c> location, or
    /// <see cref="WellKnownEndpointNames.MetadataOAuthAuthorizationServer"/> for
    /// the RFC 8414 §3 default <c>oauth-authorization-server</c> location formed
    /// by path insertion. RFC 8414 §3.1 permits publishing the same metadata at
    /// multiple well-known locations, so both candidates run this one body
    /// builder and serve a byte-identical document for the same tenant.
    /// </summary>
    /// <param name="roleName">
    /// The <see cref="WellKnownEndpointNames"/> role this candidate carries; the
    /// application's <c>ResolveEndpointUriAsync</c> maps it to the served URL.
    /// </param>
    /// <remarks>
    /// <para>
    /// The endpoint is stateless:
    /// <see cref="ServerEndpoint.BuildInputAsync"/> resolves the issuer via
    /// <see cref="Verifiable.Server.ServerIntegration.ResolveIssuerAsync"/>
    /// (falling back to <see cref="DefaultIssuerResolver"/>), then asks the
    /// application's
    /// <see cref="Verifiable.Server.ServerIntegration.ResolveEndpointUriAsync"/>
    /// for the absolute URL of each capability-gated endpoint, optionally
    /// merges fields from
    /// <see cref="AuthorizationServerIntegration.ContributeDiscoveryFieldsAsync"/>,
    /// and short-circuits the dispatcher with an early
    /// <see cref="ServerHttpResponse.Ok(string, string)"/> result.
    /// <see cref="ServerEndpoint.BuildResponse"/> is never reached.
    /// </para>
    /// <para>
    /// The library never composes paths; each advertised URL comes from the
    /// per-request <see cref="EndpointChain"/> the dispatcher placed on the
    /// context. Endpoints are projected through
    /// <see cref="Verifiable.Server.ServerIntegration.ResolveEndpointUriAsync"/>
    /// at chain-build time; discovery emission then reads
    /// <see cref="ServerEndpoint.ResolvedUri"/> directly, guaranteeing the
    /// advertised URL is the same URL the matcher will match against.
    /// </para>
    /// <para>
    /// <c>protected_resources</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-4">RFC 9728 Section 4</see>) is written once
    /// (<see cref="ProtectedResourcesOf"/>): the identifiers of the library's own resources whose document locations the
    /// request's chain derives, in the chain's order, then the values of the <c>protected_resources</c> string arrays
    /// the application's contribution names, a value already listed omitted, and the member omitted when it holds none
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.2">RFC 8414 Section 3.2</see>: "Claims with zero
    /// elements MUST be omitted from the response."). A library resource whose document request is refused, for a
    /// contribution stating a member the library composes or for a location another document shares, is still a
    /// resource of this server and stays listed. Both sides hold facts about the set Section 4 describes: the
    /// library knows the resources it serves and the application the ones only it knows, and Section 4's
    /// "Authorization servers MAY choose not to advertise some supported protected resources even when this parameter
    /// is used." makes a shorter list conformant but never one that drops what the application knows. The contribution
    /// is therefore read once per document request, before that member is written; its other fields are appended after
    /// the base set, and a wired delegate answering <see langword="null"/> in place of
    /// <see cref="DiscoveryDocumentContribution.Empty"/> is refused with <see cref="InvalidOperationException"/>.
    /// </para>
    /// <para>
    /// The JSON body is assembled by hand using <see cref="StringBuilder"/>
    /// via the helpers <see cref="AppendField"/> and
    /// <see cref="AppendContributedField"/>. See the serialization-firewall
    /// paragraph in the remarks on <see cref="MetadataEndpoints"/> for the
    /// rationale.
    /// </para>
    /// </remarks>
    private static EndpointCandidate BuildDiscovery(string roleName) =>
        new()
        {
            Name = roleName,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //DiscoveryMetadataKey is null — the discovery endpoint isn't itself
            //advertised in the discovery document; clients hit a well-known URL.

            //Acceptance test: GET to the discovery URL for this registration.
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
                AuthorizationServerIntegration oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
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
                    issuer = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false))!
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

                ResolveSupportedSigningAlgorithmsDelegate resolveSigningAlgorithms =
                    oauth.Cryptography.ResolveSupportedSigningAlgorithmsAsync
                    ?? ((resolvedRegistration, usage, requestContext, cancellationToken) =>
                        DefaultSupportedSigningAlgorithms.ResolveAsync(
                            oauth, resolvedRegistration, usage, requestContext, cancellationToken));

                StringBuilder sb = JsonAppender.Rent();
                string discoveryJson;
                try
                {
                    _ = sb.Append('{');

                    //Every member name the base emission writes, so a contributed field
                    //(below, via AppendContributedField) naming one of them is refused
                    //rather than silently duplicated (RFC 8259 §4: "The names within an
                    //object SHOULD be unique"). Threaded through every Append*Field call
                    //in this method rather than kept as a separate list, so the set can
                    //never drift from what was actually written.
                    HashSet<string> emittedFieldNames = new(StringComparer.Ordinal);

                    //RFC 8414 §3.3: the issuer value in the metadata MUST be IDENTICAL to
                    //the issuer identifier used to build the metadata URL. Emit it verbatim
                    //(OriginalString) — GetLeftPart(UriPartial.Authority) stripped any path
                    //segment and broke exact-match for path-bearing / multi-tenant issuers
                    //(the same fix already applied in Rfc9068AccessTokenProducer).
                    string issuerValue = issuer.OriginalString;
                    bool issuerFirst = true;
                    JsonAppender.AppendStringField(sb, "issuer", issuerValue, ref issuerFirst);
                    _ = emittedFieldNames.Add("issuer");

                    //Endpoint emission walks the per-request
                    //EndpointChain. The dispatcher places it on the context after
                    //ResolveCapabilitiesAsync attenuation and per-candidate URL
                    //resolution, so this loop emits exactly the endpoints active
                    //for this request: capability-vetoed endpoints are absent,
                    //and the advertised URL is the same Uri the matcher will
                    //match against (no drift possible because both read
                    //ServerEndpoint.ResolvedUri).
                    //
                    //Endpoints share a DiscoveryMetadataKey when they share a URL
                    //(JAR variants of PAR/Authorize advertise under their non-JAR
                    //sibling's key; refresh-token shares the token endpoint URL).
                    //The JAR variants, refresh-token and UserInfo's POST candidate
                    //carry DiscoveryMetadataKey=null specifically to avoid double-
                    //emission, so the skip-null guard below is the only
                    //deduplication this loop needs.
                    EndpointChain? chain = context.EndpointChain;
                    if(chain is null)
                    {
                        return (null, ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            "EndpointChain not on context for discovery emission. "
                            + "DispatchAsync sets this; this code path is only "
                            + "reachable through dispatch."));
                    }

                    bool authorizationCodeOnChain = false;
                    bool refreshTokenOnChain = false;
                    bool tokenEndpointOnChain = false;
                    bool clientCredentialsOnChain = false;
                    bool preAuthorizedCodeOnChain = false;
                    bool introspectionOnChain = false;
                    bool tokenExchangeOnChain = false;
                    bool jwtBearerOnChain = false;
                    foreach(ServerEndpoint chainEndpoint in chain)
                    {
                        if(chainEndpoint.Capability == WellKnownCapabilityIdentifiers.OAuthAuthorizationCode)
                        {
                            authorizationCodeOnChain = true;
                        }
                        if(string.Equals(chainEndpoint.Name,
                            WellKnownEndpointNames.AuthCodeRefreshToken, StringComparison.Ordinal))
                        {
                            refreshTokenOnChain = true;
                        }
                        if(string.Equals(chainEndpoint.Name,
                            WellKnownEndpointNames.AuthCodeToken, StringComparison.Ordinal))
                        {
                            tokenEndpointOnChain = true;
                        }
                        if(string.Equals(chainEndpoint.Name,
                            WellKnownEndpointNames.ClientCredentialsToken, StringComparison.Ordinal))
                        {
                            clientCredentialsOnChain = true;
                        }
                        if(string.Equals(chainEndpoint.Name,
                            WellKnownEndpointNames.Oid4VciPreAuthorizedToken, StringComparison.Ordinal))
                        {
                            preAuthorizedCodeOnChain = true;
                        }
                        if(string.Equals(chainEndpoint.Name,
                            WellKnownEndpointNames.AuthCodeIntrospect, StringComparison.Ordinal))
                        {
                            introspectionOnChain = true;
                        }
                        if(string.Equals(chainEndpoint.Name,
                            WellKnownEndpointNames.TokenExchangeToken, StringComparison.Ordinal))
                        {
                            tokenExchangeOnChain = true;
                        }
                        if(string.Equals(chainEndpoint.Name,
                            WellKnownEndpointNames.JwtBearerToken, StringComparison.Ordinal))
                        {
                            jwtBearerOnChain = true;
                        }

                        if(chainEndpoint.DiscoveryMetadataKey is null) { continue; }
                        AppendField(
                            sb,
                            chainEndpoint.DiscoveryMetadataKey,
                            chainEndpoint.ResolvedUri.ToString(),
                            emittedFieldNames);
                    }

                    //OIDC Discovery 1.0 §3 REQUIRED fields. The library's subject
                    //identifier story is "public" by default (the application
                    //installs a custom ResolveSubjectIdentifierAsync to add the
                    //pairwise option).
                    AppendStringArrayField(
                        sb,
                        OpenIdProviderMetadataParameterNames.SubjectTypesSupported,
                        SubjectTypePublic,
                        emittedFieldNames);

                    //response_types_supported — derived from the per-request chain
                    //to match the existing endpoint-URL emission's attenuation
                    //semantics. Authorization Code is the only OAuth 2.1-conformant
                    //response type the library ships; hybrid / implicit flows are
                    //out of scope.
                    if(authorizationCodeOnChain)
                    {
                        AppendStringArrayField(
                            sb,
                            AuthorizationServerMetadataParameterNames.ResponseTypesSupported,
                            ResponseTypeCode,
                            emittedFieldNames);
                    }

                    //All signing-algorithm members use the same per-usage input.
                    //The default resolves current key tags; a host can supply the
                    //complete set independently of per-consumer key selection.
                    IReadOnlyList<string> idTokenAlgs = await resolveSigningAlgorithms(
                        registration, KeyUsageContext.IdTokenIssuance, context, ct).ConfigureAwait(false);
                    if(idTokenAlgs.Count > 0)
                    {
                        AppendStringArrayField(
                            sb,
                            OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported,
                            idTokenAlgs,
                            emittedFieldNames);
                    }

                    //grant_types_supported (RFC 8414 §2 OPTIONAL). The library
                    //ships the authorization_code grant; refresh_token is added
                    //when the registration enables refresh-token endpoints.
                    //Defaults from RFC 6749 / OIDC Core (authorization_code +
                    //implicit) intentionally not used — implicit is out of scope
                    //per OAuth 2.1 / FAPI 2.0.
                    if(authorizationCodeOnChain || clientCredentialsOnChain || preAuthorizedCodeOnChain
                        || tokenExchangeOnChain || jwtBearerOnChain)
                    {
                        List<string> grantTypes = new(6);
                        if(authorizationCodeOnChain)
                        {
                            grantTypes.Add(WellKnownGrantTypes.AuthorizationCode);
                            if(refreshTokenOnChain)
                            {
                                grantTypes.Add(WellKnownGrantTypes.RefreshToken);
                            }
                        }

                        if(clientCredentialsOnChain)
                        {
                            grantTypes.Add(WellKnownGrantTypes.ClientCredentials);
                        }

                        if(preAuthorizedCodeOnChain)
                        {
                            grantTypes.Add(WellKnownGrantTypes.PreAuthorizedCode);
                        }

                        if(tokenExchangeOnChain)
                        {
                            grantTypes.Add(WellKnownGrantTypes.TokenExchange);
                        }

                        //ID-JAG §7.2: a Resource Authorization Server advertising the id-jag grant profile
                        //MUST also include the jwt-bearer grant type. The profile is advertised below under
                        //the same jwtBearerOnChain condition, so adding jwt-bearer here satisfies that MUST.
                        if(jwtBearerOnChain)
                        {
                            grantTypes.Add(WellKnownGrantTypes.JwtBearer);
                        }

                        AppendStringArrayField(
                            sb,
                            AuthorizationServerMetadataParameterNames.GrantTypesSupported,
                            grantTypes,
                            emittedFieldNames);
                    }

                    //ID-JAG §7.1: an IdP Authorization Server that can mint an Identity Assertion JWT
                    //Authorization Grant via Token Exchange SHOULD advertise the id-jag token type in
                    //identity_chaining_requested_token_types_supported.
                    if(tokenExchangeOnChain)
                    {
                        AppendStringArrayField(
                            sb,
                            AuthorizationServerMetadataParameterNames.IdentityChainingRequestedTokenTypesSupported,
                            [TokenTypeNames.GetName(TokenType.IdJag)],
                            emittedFieldNames);
                    }

                    //ID-JAG §7.2: a Resource Authorization Server that processes the id-jag grant — it
                    //consumes an ID-JAG as a jwt-bearer assertion — SHOULD advertise the grant profile in
                    //authorization_grant_profiles_supported.
                    if(jwtBearerOnChain)
                    {
                        AppendStringArrayField(
                            sb,
                            AuthorizationServerMetadataParameterNames.AuthorizationGrantProfilesSupported,
                            [WellKnownGrantProfiles.IdJag],
                            emittedFieldNames);
                    }

                    //pre-authorized_grant_anonymous_access_supported (OID4VCI 1.0 §12.3 OPTIONAL):
                    //"A boolean indicating whether the Credential Issuer accepts a Token Request with
                    //a Pre-Authorized Code but without a client_id. The default is false." Advertised
                    //only when the §6 Pre-Authorized Code token endpoint is on the chain AND the
                    //deployment opted in via policy — the advertisement matches what the
                    //ValidatePreAuthorizedCodeAsync seam will accept (it denies an anonymous request
                    //with ClientAuthenticationRequired when the deployment requires authentication).
                    //Omitted (rather than emitted false) when not opted in, since false is the §12.3
                    //default the Wallet assumes for an absent parameter.
                    if(preAuthorizedCodeOnChain && context.PreAuthorizedGrantAnonymousAccessSupported)
                    {
                        AppendBooleanField(
                            sb,
                            AuthorizationServerMetadataParameterNames.PreAuthorizedGrantAnonymousAccessSupported,
                            true,
                            emittedFieldNames);
                    }

                    //authorization_details_types_supported (RFC 9396 Section 10), under the one rule
                    //the documents of the OID4VCI resources read too: a token grant that can process
                    //authorization_details on the chain AND the decision seam that mints the OID4VCI
                    //Section 6.2 credential_identifiers wired.
                    if(IsAuthorizationDetailsProcessingAdvertised(chain, oauth))
                    {
                        AppendStringArrayField(
                            sb,
                            AuthorizationServerMetadataParameterNames.AuthorizationDetailsTypesSupported,
                            oauth.AuthorizationDetailTypes.RegisteredTypes,
                            emittedFieldNames);
                    }

                    //The application's fields, read before protected_resources is written: a
                    //protected_resources string array it names joins the one member below, and the
                    //rest are appended after the base set. The null local stands for the unwired
                    //delegate alone; a wired delegate answers DiscoveryDocumentContribution.Empty
                    //when it has nothing to contribute, so a null answer is refused.
                    DiscoveryDocumentContribution? contributed = oauth.ContributeDiscoveryFieldsAsync is null
                        ? null
                        : await oauth.ContributeDiscoveryFieldsAsync(registration, context, ct).ConfigureAwait(false)
                            ?? throw new InvalidOperationException(
                                "The discovery document contribution delegate ContributeDiscoveryFieldsAsync answered "
                                + "null. A contribution delegate with nothing to contribute must answer "
                                + "DiscoveryDocumentContribution.Empty.");

                    //protected_resources (RFC 9728 Section 4): the identifiers of the library's own
                    //resources whose document locations this chain derives, in the chain's order, then the
                    //resources the application names; each value once, and the member omitted when
                    //it holds none (RFC 8414 Section 3.2).
                    AppendStringArrayField(
                        sb,
                        AuthorizationServerMetadataParameterNames.ProtectedResources,
                        ProtectedResourcesOf(chain, contributed),
                        emittedFieldNames);

                    //JARM §4: advertise the JWT-secured response modes and signing algorithms
                    //when the authorize endpoint is on the chain AND the input declares
                    //authorization-response signing support — an advertisement without support
                    //would invite response_mode requests the server refuses with invalid_request.
                    if(authorizationCodeOnChain)
                    {
                        IReadOnlyList<string> jarmAlgs = await resolveSigningAlgorithms(
                            registration, KeyUsageContext.AuthorizationResponseSigning, context, ct).ConfigureAwait(false);
                        if(jarmAlgs.Count > 0)
                        {
                            AppendStringArrayField(
                                sb,
                                AuthorizationServerMetadataParameterNames.ResponseModesSupported,
                                [
                                    "query",
                                    "fragment",
                                    "form_post",
                                    Jarm.JarmResponseModes.QueryJwt,
                                    Jarm.JarmResponseModes.FragmentJwt,
                                    Jarm.JarmResponseModes.FormPostJwt,
                                    Jarm.JarmResponseModes.Jwt
                                ],
                                emittedFieldNames);
                            AppendStringArrayField(
                                sb,
                                Jarm.JarmServerMetadataParameterNames.AuthorizationSigningAlgValuesSupported,
                                jarmAlgs,
                                emittedFieldNames);
                        }
                    }

                    //RFC 9701 §7: advertise the introspection-response signing algorithms when
                    //the introspection endpoint is on the chain AND the input declares
                    //introspection-response signing support — an advertisement without support
                    //would invite Accept: application/token-introspection+jwt requests the
                    //server refuses with invalid_request.
                    if(introspectionOnChain)
                    {
                        IReadOnlyList<string> introspectionAlgs = await resolveSigningAlgorithms(
                            registration, KeyUsageContext.IntrospectionResponseSigning, context, ct).ConfigureAwait(false);
                        if(introspectionAlgs.Count > 0)
                        {
                            AppendStringArrayField(
                                sb,
                                Introspection.IntrospectionServerMetadataParameterNames.IntrospectionSigningAlgValuesSupported,
                                introspectionAlgs,
                                emittedFieldNames);
                        }
                    }

                    //RFC 8414 §2 advertises S256 only: OAuth 2.1 §7.5.2 forbids plain under every profile.
                    if(authorizationCodeOnChain)
                    {
                        AppendStringArrayField(
                            sb,
                            AuthorizationServerMetadataParameterNames.CodeChallengeMethodsSupported,
                            CodeChallengeMethodS256,
                            emittedFieldNames);

                        //FAPI 2.0 Security Profile Section 5.3.2.2 / RFC 9207: advertise whether PAR is mandatory and
                        //whether the iss authorization-response parameter is emitted. Both
                        //come from the resolved policy so the advertisement matches enforcement.
                        AppendBooleanField(
                            sb,
                            AuthorizationServerMetadataParameterNames.RequirePushedAuthorizationRequests,
                            context.RequirePushedAuthorizationRequests,
                            emittedFieldNames);
                        AppendBooleanField(
                            sb,
                            AuthorizationServerMetadataParameterNames.AuthorizationResponseIssParameterSupported,
                            context.EmitIssOnRedirect,
                            emittedFieldNames);
                    }

                    //RFC 9449 §5.1 — advertise the DPoP proof signature algorithms the AS
                    //accepts whenever DPoP validation is wired, the application's validator or
                    //the library default (FAPI 2.0 sender-constrained tokens). Independent of
                    //the authorize-endpoint chain. Only the ones a proof can be accepted under are
                    //supported (RFC 9449 Section 11.6: "In particular, the algorithm none MUST NOT
                    //be allowed."), so the host's list is advertised through the one filter the
                    //resources' challenges read.
                    if(Dpop.DpopRequestReading.IsProofValidationWired(oauth))
                    {
                        IReadOnlyList<string> dpopAlgs = Dpop.DpopProofValidator.AcceptableProofAlgorithms(await resolveSigningAlgorithms(
                            registration, KeyUsageContext.DpopProof, context, ct).ConfigureAwait(false));
                        AppendStringArrayField(
                            sb,
                            AuthorizationServerMetadataParameterNames.DpopSigningAlgValuesSupported,
                            dpopAlgs,
                            emittedFieldNames);
                    }

                    //OIDC Back-Channel Logout 1.0 §4: advertise back-channel logout only when the
                    //capability is allowed AND the fan-out seam is wired (fail-closed). The OP is
                    //the sender — there is no OP endpoint to chain — so the boolean flags are
                    //emitted here rather than via a candidate's DiscoveryMetadataKey. The OP
                    //includes a sid in its Logout Tokens (the per-session sid), so session-based
                    //back-channel logout is supported too. The capability is read from the set the
                    //request is served under, held to the bound, so the document advertises only what
                    //the end-session fan-out sends.
                    if(context.IsBoundedCapabilityAllowed(WellKnownCapabilityIdentifiers.OidcBackChannelLogout)
                        && oauth.DeliverBackChannelLogoutAsync is not null)
                    {
                        AppendBooleanField(
                            sb,
                            AuthorizationServerMetadataParameterNames.BackchannelLogoutSupported,
                            true,
                            emittedFieldNames);
                        AppendBooleanField(
                            sb,
                            AuthorizationServerMetadataParameterNames.BackchannelLogoutSessionSupported,
                            true,
                            emittedFieldNames);
                    }

                    //draft-ietf-oauth-client-id-metadata-document-02 §6: advertise
                    //client_id_metadata_document_supported only when the capability is
                    //allowed AND the CIMD resolver seam is wired (fail-closed) — mirroring
                    //the back-channel-logout dual gate above. CIMD applies AS-wide (any
                    //grant a URL-shaped client_id can drive), so this is not gated on
                    //authorizationCodeOnChain. The capability is read from the set the request is
                    //served under, held to the bound.
                    if(context.IsBoundedCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument)
                        && oauth.ResolveClientMetadataAsync is not null)
                    {
                        AppendBooleanField(
                            sb,
                            AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported,
                            true,
                            emittedFieldNames);
                    }

                    //token_endpoint_auth_methods_supported (RFC 8414 §2 OPTIONAL): "JSON
                    //array containing a list of client authentication methods supported
                    //by this token endpoint. ... If omitted, the default is
                    //'client_secret_basic'." Emitted from the deployment's own
                    //declaration whenever the token endpoint is on chain — omission
                    //would advertise client_secret_basic, which the library does not
                    //judge by default (RequireClientAuthenticationIfDeclaredAsync judges
                    //every method through the single ValidateClientCredentialsAsync
                    //seam, never a built-in client_secret_basic path).
                    if(tokenEndpointOnChain)
                    {
                        string[] authMethodNames = [.. oauth.ClientAuthenticationMethodsSupported
                            .Select(ClientAuthenticationMethodNames.GetName)];
                        AppendStringArrayField(
                            sb,
                            AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported,
                            authMethodNames,
                            emittedFieldNames);

                        //token_endpoint_auth_signing_alg_values_supported (RFC 8414 §2
                        //OPTIONAL) describes accepted client signatures. The default
                        //retains ClientAssertionSigningAlgorithmsSupported; an override
                        //must describe the algorithms the host actually accepts.
                        IReadOnlyList<string> clientAssertionAlgs = await resolveSigningAlgorithms(
                            registration, KeyUsageContext.ClientAssertion, context, ct).ConfigureAwait(false);
                        AppendStringArrayField(
                            sb,
                            AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupported,
                            clientAssertionAlgs,
                            emittedFieldNames);
                    }

                    //scopes_supported (OIDC Discovery §3 RECOMMENDED). Derived
                    //from the registration's per-tenant AllowedScopes set; sorted
                    //lexicographically for deterministic wire output across
                    //ImmutableHashSet's iteration order. Omitted when the
                    //registration has no scopes configured.
                    if(registration.AllowedScopes.Count > 0)
                    {
                        string[] sortedScopes = registration.AllowedScopes
                            .OrderBy(static s => s, StringComparer.Ordinal)
                            .ToArray();
                        AppendStringArrayField(
                            sb,
                            AuthorizationServerMetadataParameterNames.ScopesSupported,
                            sortedScopes,
                            emittedFieldNames);
                    }

                    //claims_supported (OIDC Discovery §3 RECOMMENDED). Lists the
                    //JWT claim names the standard
                    //ContributionProfiles.StandardClaimIssuer rules can emit, plus
                    //the spec-required sub. The list is aspirational per OIDC
                    //Discovery §3 — the OP is not guaranteed to populate every
                    //advertised claim for every request; scope / authentication-
                    //context drives actual emission. The list reflects what the
                    //standard rules emit; a claims_supported field contributed
                    //through ContributeDiscoveryFieldsAsync is refused while the
                    //library writes the member here. Gated on authorization_code
                    //chain presence because the field is OIDC-specific.
                    if(authorizationCodeOnChain)
                    {
                        AppendStringArrayField(
                            sb,
                            OpenIdProviderMetadataParameterNames.ClaimsSupported,
                            StandardClaimsSupported,
                            emittedFieldNames);

                        //claim_types_supported (OIDC Core §5.6 / OIDC Discovery §3
                        //OPTIONAL). The library supplies claim values directly
                        //(normal claim type per §5.6.1); aggregated and distributed
                        //claim types are not implemented. Default per OIDC
                        //Discovery §3 is ["normal"] when the field is absent;
                        //emitting it explicitly is the unambiguous form.
                        AppendStringArrayField(
                            sb,
                            OpenIdProviderMetadataParameterNames.ClaimTypesSupported,
                            ClaimTypeNormal,
                            emittedFieldNames);
                    }

                    //Application-supplied additional fields merged after the base set, but for the
                    //protected_resources lists already merged into that member.
                    if(contributed is not null)
                    {
                        foreach(DiscoveryField field in contributed.Fields)
                        {
                            if(IsContributedProtectedResourcesList(field))
                            {
                                continue;
                            }

                            AppendContributedField(sb, field, emittedFieldNames);
                        }
                    }

                    _ = sb.Append('}');

                    discoveryJson = sb.ToString();
                }
                finally
                {
                    JsonAppender.Return(sb);
                }

                return (null, ServerHttpResponse.Ok(discoveryJson, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    //Helpers go below the public surface.

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
    /// <param name="emittedFieldNames">
    /// The per-document set of member names the base emission has written so far;
    /// <paramref name="key"/> is recorded into it so a later contributed field of
    /// the same name is refused (RFC 8259 §4).
    /// </param>
    private static void AppendField(StringBuilder sb, string key, string value, HashSet<string> emittedFieldNames)
    {
        //Discovery callers always emit issuer first, so subsequent fields
        //carry a leading comma. Threading first=false into JsonAppender
        //preserves that contract while routing escape through the shared
        //primitive.
        bool first = false;
        JsonAppender.AppendStringField(sb, key, value, ref first);
        _ = emittedFieldNames.Add(key);
    }


    /// <summary>
    /// Appends a string-array field to the discovery-document builder,
    /// formatted as <c>,"key":["v1","v2",…]</c>. Always emits the leading
    /// comma; callers must have written the opening brace and at least the
    /// <c>issuer</c> field before calling. No-ops on an empty list to avoid
    /// emitting <c>"key":[]</c> for fields that should be omitted entirely
    /// when no values are available — and correspondingly does not record
    /// <paramref name="key"/> into <paramref name="emittedFieldNames"/> when
    /// nothing was written.
    /// </summary>
    /// <param name="emittedFieldNames">
    /// The per-document set of member names the base emission has written so far;
    /// <paramref name="key"/> is recorded into it when the array is non-empty, so a
    /// later contributed field of the same name is refused (RFC 8259 §4).
    /// </param>
    /// <param name="sb">The discovery-document builder to append the field to.</param>
    /// <param name="key">The wire field name to emit.</param>
    /// <param name="values">The values to emit as the JSON array; an empty list omits the field.</param>
    private static void AppendStringArrayField(
        StringBuilder sb, string key, IReadOnlyList<string> values, HashSet<string> emittedFieldNames)
    {
        if(values.Count == 0) { return; }

        bool first = false;
        JsonAppender.AppendStringArrayField(sb, key, values, ref first);
        _ = emittedFieldNames.Add(key);
    }


    /// <summary>
    /// Appends a boolean field to the discovery-document builder, formatted as
    /// <c>,"key":true|false</c>. Always emits the leading comma; callers must have
    /// written the opening brace and at least the <c>issuer</c> field first.
    /// </summary>
    /// <param name="emittedFieldNames">
    /// The per-document set of member names the base emission has written so far;
    /// <paramref name="key"/> is recorded into it so a later contributed field of
    /// the same name is refused (RFC 8259 §4).
    /// </param>
    /// <param name="sb">The discovery-document builder to append the field to.</param>
    /// <param name="key">The wire field name to emit.</param>
    /// <param name="value">The boolean value to emit.</param>
    private static void AppendBooleanField(StringBuilder sb, string key, bool value, HashSet<string> emittedFieldNames)
    {
        bool first = false;
        JsonAppender.AppendBoolField(sb, key, value, ref first);
        _ = emittedFieldNames.Add(key);
    }


    /// <summary>
    /// Whether the server advertises the authorization details types it processes: a token grant that processes
    /// <c>authorization_details</c> is on the request's <paramref name="chain"/> (the authorization code grant, by its
    /// capability, or the OID4VCI pre-authorized code token endpoint, by its name) and the decision seam that mints the
    /// OID4VCI credential identifiers, <see cref="AuthorizationServerIntegration.ResolveCredentialAuthorizationAsync"/>,
    /// is wired, so an advertisement never invites a request the server refuses with
    /// <c>invalid_authorization_details</c>. The one rule for the authorization server document, which names the whole
    /// registry, <see cref="AuthorizationDetailTypeRegistry.RegisteredTypes"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9396#section-10">RFC 9396 Section 10</see>: "To advertise its
    /// support for this feature, the supported list of authorization details types is included in the AS metadata
    /// response [RFC8414] using the metadata parameter authorization_details_types_supported, which is a JSON array."),
    /// and for the documents of the credential issuer's resources, each of which names the types that resource
    /// processes and the registry holds
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "authorization_details_types_supported OPTIONAL. JSON array containing a list of the authorization details type
    /// values supported by the resource server when the authorization_details request parameter [RFC9396] is used.").
    /// </summary>
    /// <param name="chain">The request's endpoint chain.</param>
    /// <param name="oauth">The authorization server's integration.</param>
    /// <returns><see langword="true"/> when the types are advertised.</returns>
    internal static bool IsAuthorizationDetailsProcessingAdvertised(EndpointChain chain, AuthorizationServerIntegration oauth)
    {
        if(oauth.ResolveCredentialAuthorizationAsync is null)
        {
            return false;
        }

        foreach(ServerEndpoint endpoint in chain)
        {
            if(endpoint.Capability == WellKnownCapabilityIdentifiers.OAuthAuthorizationCode
                || string.Equals(endpoint.Name, WellKnownEndpointNames.Oid4VciPreAuthorizedToken, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// The values of the discovery document's one <c>protected_resources</c> member
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-4">RFC 9728 Section 4</see>: "JSON array containing a
    /// list of resource identifiers for OAuth protected resources that can be used with this authorization server."):
    /// first the identifier of each of the library's own resources whose document location the request's
    /// <paramref name="chain"/> derives, in the chain's order
    /// (<see cref="ProtectedResourceMetadataEndpoints.TryDeriveLibraryResourceDocument"/>, the
    /// derivation the documents and the challenges read; a resource whose document request is refused, for a
    /// contribution stating a member the library composes or for a location another document shares, is still a
    /// resource of this server, so the list reads neither refusal), then the values of
    /// each <c>protected_resources</c> string array the application's <paramref name="contributed"/> fields name, in
    /// their order, for the resources only the application knows; a value already listed is omitted (ordinal equality).
    /// </summary>
    /// <param name="chain">The request's endpoint chain.</param>
    /// <param name="contributed">The application's discovery contribution, or <see langword="null"/>.</param>
    /// <returns>The identifiers; empty when the server lists none.</returns>
    private static List<string> ProtectedResourcesOf(EndpointChain chain, DiscoveryDocumentContribution? contributed)
    {
        List<string> resources = [];
        foreach(ServerEndpoint endpoint in chain)
        {
            if(ProtectedResourceMetadataEndpoints.LibraryResourceEndpointNames.Contains(endpoint.Name, StringComparer.Ordinal)
                && ProtectedResourceMetadataEndpoints.TryDeriveLibraryResourceDocument(
                    chain, endpoint.Name, out string? identifier, out _))
            {
                AddOnce(resources, identifier);
            }
        }

        if(contributed is not null)
        {
            foreach(DiscoveryField field in contributed.Fields)
            {
                if(field is DiscoveryStringArrayField list && IsContributedProtectedResourcesList(list))
                {
                    foreach(string value in list.Values)
                    {
                        AddOnce(resources, value);
                    }
                }
            }
        }

        return resources;
    }


    /// <summary>
    /// Adds <paramref name="value"/> to <paramref name="values"/> unless an ordinally equal value is already there, so a
    /// list member names each value once.
    /// </summary>
    /// <param name="values">The list being composed.</param>
    /// <param name="value">The value.</param>
    private static void AddOnce(List<string> values, string value)
    {
        if(!values.Contains(value, StringComparer.Ordinal))
        {
            values.Add(value);
        }
    }


    /// <summary>
    /// Whether the contributed <paramref name="field"/> is a <c>protected_resources</c> string array, which joins the
    /// one member the library writes (<see cref="ProtectedResourcesOf"/>) rather than being appended as a field of its
    /// own; a <c>protected_resources</c> field of another record type is appended as any other contributed field is.
    /// </summary>
    /// <param name="field">The contributed field.</param>
    /// <returns><see langword="true"/> when the field is such a list.</returns>
    private static bool IsContributedProtectedResourcesList(DiscoveryField field) =>
        field is DiscoveryStringArrayField
        && string.Equals(field.Name, AuthorizationServerMetadataParameterNames.ProtectedResources, StringComparison.Ordinal);


    /// <summary>The public subject-identifier type advertised by discovery.</summary>
    private static IReadOnlyList<string> SubjectTypePublic { get; } = ["public"];


    /// <summary>The authorization-code response type advertised by discovery.</summary>
    private static IReadOnlyList<string> ResponseTypeCode { get; } = ["code"];


    /// <summary>The RFC 8414 §2 method advertisement; OAuth 2.1 §7.5.2 forbids plain.</summary>
    private static IReadOnlyList<string> CodeChallengeMethodS256 { get; } =
        [WellKnownCodeChallengeMethods.S256];


    /// <summary>The normal claim type advertised by discovery.</summary>
    private static IReadOnlyList<string> ClaimTypeNormal { get; } = ["normal"];

    /// <summary>
    /// JWT claim names the standard
    /// <see cref="ContributionProfiles.StandardClaimIssuer"/> rules can emit,
    /// plus the spec-required <c>sub</c>. Sorted ordinally for deterministic
    /// wire output. Synchronisation invariant: every name added to or removed
    /// from the standard contributors must update this
    /// list. The <c>ContributorChainRegressionTests</c> baseline pins
    /// the contributor output; this list pins the wire advertisement.
    /// </summary>
    private static IReadOnlyList<string> StandardClaimsSupported { get; } =
    [
        //OIDC Core §2 spec-required.
        WellKnownJwtClaimNames.Sub,

        //OIDC Core §2 authentication-context (AcrAmrClaimContributor).
        WellKnownJwtClaimNames.Acr,
        WellKnownJwtClaimNames.Amr,
        WellKnownJwtClaimNames.AuthTime,

        //OIDC Core §5.4 profile scope (OidcStandardClaimsContributor.GenerateProfileClaims).
        WellKnownJwtClaimNames.Name,
        WellKnownJwtClaimNames.FamilyName,
        WellKnownJwtClaimNames.GivenName,
        WellKnownJwtClaimNames.MiddleName,
        WellKnownJwtClaimNames.Nickname,
        WellKnownJwtClaimNames.PreferredUsername,
        WellKnownJwtClaimNames.Profile,
        WellKnownJwtClaimNames.Picture,
        WellKnownJwtClaimNames.Website,
        WellKnownJwtClaimNames.Gender,
        WellKnownJwtClaimNames.Birthdate,
        WellKnownJwtClaimNames.Zoneinfo,
        WellKnownJwtClaimNames.Locale,
        WellKnownJwtClaimNames.UpdatedAt,

        //OIDC Core §5.4 email scope.
        WellKnownJwtClaimNames.Email,
        WellKnownJwtClaimNames.EmailVerified,

        //OIDC Core §5.4 / §5.1.1 address scope (structured object).
        WellKnownJwtClaimNames.Address,

        //OIDC Core §5.4 phone scope.
        WellKnownJwtClaimNames.PhoneNumber,
        WellKnownJwtClaimNames.PhoneNumberVerified,

        //RFC 7800 / RFC 9449 §6.1 confirmation (CnfClaimContributor).
        WellKnownJwtClaimNames.Cnf
    ];


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
    /// runtime CLR-type inspection. A field naming a member already present in
    /// <paramref name="emittedFieldNames"/> — one the base emission wrote, or an
    /// earlier contributed field of the same name — is a composition defect
    /// (RFC 8259 §4: "The names within an object SHOULD be unique") and is
    /// refused rather than written, so the document never carries a duplicate
    /// name. A <c>protected_resources</c> string array never reaches this method:
    /// its values join the one <c>protected_resources</c> member the library
    /// writes (<see cref="ProtectedResourcesOf"/>), since the library's own
    /// resources and the application's are facts about the one set RFC 9728
    /// Section 4 lists. A <c>protected_resources</c> field of another record type
    /// is refused here when the library wrote the member and written as given
    /// when it wrote none.
    /// </remarks>
    /// <param name="sb">The <see cref="StringBuilder"/> the field is written to.</param>
    /// <param name="field">The contributed field, dispatched on its record subtype.</param>
    /// <param name="emittedFieldNames">The per-document set of member names already written.</param>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="field"/>'s <see cref="DiscoveryField.Name"/> is already in
    /// <paramref name="emittedFieldNames"/>.
    /// </exception>
    private static void AppendContributedField(StringBuilder sb, DiscoveryField field, HashSet<string> emittedFieldNames)
    {
        if(!emittedFieldNames.Add(field.Name))
        {
            throw new InvalidOperationException(
                $"The discovery document contribution names '{field.Name}', which the base "
                + "discovery emission already wrote. A contributed field must not duplicate a "
                + "member the library emits; remove it from the contribution.");
        }

        bool first = false;
        _ = field switch
        {
            DiscoveryStringField stringField => AppendStringValue(stringField),
            DiscoveryBooleanField booleanField => AppendBooleanValue(booleanField),
            DiscoveryNumberField numberField => AppendNumberValue(numberField),
            DiscoveryStringArrayField arrayField => AppendStringArrayValue(arrayField),

            //Library invariant: the DiscoveryField hierarchy is closed
            //and exhaustively handled above. A new subtype added without
            //updating this dispatch is a library bug.
            _ => throw new InvalidOperationException(
                $"Unhandled discovery field record subtype '{field.GetType().FullName}'.")
        };


        bool AppendStringValue(DiscoveryStringField stringField)
        {
            JsonAppender.AppendStringField(sb, field.Name, stringField.Value, ref first);

            return true;
        }


        bool AppendBooleanValue(DiscoveryBooleanField booleanField)
        {
            JsonAppender.AppendBoolField(sb, field.Name, booleanField.Value, ref first);

            return true;
        }


        bool AppendNumberValue(DiscoveryNumberField numberField)
        {
            JsonAppender.AppendInt64Field(sb, field.Name, numberField.Value, ref first);

            return true;
        }


        bool AppendStringArrayValue(DiscoveryStringArrayField arrayField)
        {
            JsonAppender.AppendStringArrayField(sb, field.Name, arrayField.Values, ref first);

            return true;
        }
    }


    /// <summary>
    /// Serializes a <see cref="JwksDocument"/> to its
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5">RFC 7517 §5</see>
    /// JSON wire form: <c>{"keys":[{...},{...}]}</c>. Each
    /// <see cref="JsonWebKey"/>'s entries are emitted in iteration order via
    /// <see cref="JsonAppender.AppendObject"/>; no field-name precedence or omission
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
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            _ = sb.Append("{\"keys\":[");

            bool first = true;
            foreach(JsonWebKey key in jwks.Keys)
            {
                if(!first)
                {
                    _ = sb.Append(',');
                }

                first = false;
                JsonAppender.AppendObject(sb, key);
            }

            _ = sb.Append("]}");

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
