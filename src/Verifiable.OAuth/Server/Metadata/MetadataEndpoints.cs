using System.Diagnostics;
using System.Globalization;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server;
namespace Verifiable.OAuth.Server.Metadata;

/// <summary>
/// Endpoint builder module for JWKS and Discovery metadata endpoints.
/// </summary>
/// <remarks>
/// <para>
/// Register at startup via <see cref="EndpointServer.EndpointBuilders"/>:
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


    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="EndpointServer.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
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
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                if(oauth.Cryptography.BuildJwksDocumentAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "BuildJwksDocumentAsync is not configured."));
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
    /// The library never composes paths; each advertised URL comes from the
    /// per-request <see cref="EndpointChain"/> the dispatcher placed on the
    /// context. Endpoints are projected through
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// at chain-build time; discovery emission then reads
    /// <see cref="ServerEndpoint.ResolvedUri"/> directly, guaranteeing the
    /// advertised URL is the same URL the matcher will match against.
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
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

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

                StringBuilder sb = JsonAppender.Rent();
                sb.Append('{');

                //RFC 8414 §3.3: the issuer value in the metadata MUST be IDENTICAL to
                //the issuer identifier used to build the metadata URL. Emit it verbatim
                //(OriginalString) — GetLeftPart(UriPartial.Authority) stripped any path
                //segment and broke exact-match for path-bearing / multi-tenant issuers
                //(the same fix already applied in Rfc9068AccessTokenProducer).
                string issuerValue = issuer.OriginalString;
                bool issuerFirst = true;
                JsonAppender.AppendStringField(sb, "issuer", issuerValue, ref issuerFirst);

                //Phase 9h chunk 9 — endpoint emission walks the per-request
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
                //Per chunk 6 the JAR variants and refresh-token carry
                //DiscoveryMetadataKey=null specifically to avoid double-
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

                    if(chainEndpoint.DiscoveryMetadataKey is null) { continue; }
                    AppendField(
                        sb,
                        chainEndpoint.DiscoveryMetadataKey,
                        chainEndpoint.ResolvedUri.ToString());
                }

                //OIDC Discovery 1.0 §3 REQUIRED fields. The library's subject
                //identifier story is "public" by default (the application
                //installs a custom ResolveSubjectIdentifierAsync to add the
                //pairwise option); chunks 12-16 will iterate on the
                //tenant-specific subject-type set in a follow-up.
                AppendStringArrayField(
                    sb,
                    OpenIdProviderMetadataParameterNames.SubjectTypesSupported,
                    SubjectTypePublic);

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
                        ResponseTypeCode);
                }

                //id_token_signing_alg_values_supported — derived from the
                //registration's IdTokenIssuance signing keys. Each KeyId is
                //resolved through the verification-key resolver and its tag
                //mapped to a JWA identifier; the deduped set forms the
                //advertised list.
                IReadOnlyList<string> idTokenAlgs = await ResolveSigningAlgValuesAsync(
                    Verifiable.Cryptography.Context.KeyUsageContext.IdTokenIssuance,
                    server, registration, context, ct).ConfigureAwait(false);
                if(idTokenAlgs.Count > 0)
                {
                    AppendStringArrayField(
                        sb,
                        OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported,
                        idTokenAlgs);
                }

                //grant_types_supported (RFC 8414 §2 OPTIONAL). The library
                //ships the authorization_code grant; refresh_token is added
                //when the registration enables refresh-token endpoints.
                //Defaults from RFC 6749 / OIDC Core (authorization_code +
                //implicit) intentionally not used — implicit is out of scope
                //per OAuth 2.1 / FAPI 2.0.
                if(authorizationCodeOnChain || clientCredentialsOnChain || preAuthorizedCodeOnChain)
                {
                    List<string> grantTypes = new(4);
                    if(authorizationCodeOnChain)
                    {
                        grantTypes.Add(OAuthRequestParameterValues.GrantTypeAuthorizationCode);
                        if(refreshTokenOnChain)
                        {
                            grantTypes.Add(OAuthRequestParameterValues.GrantTypeRefreshToken);
                        }
                    }

                    if(clientCredentialsOnChain)
                    {
                        grantTypes.Add(OAuthRequestParameterValues.GrantTypeClientCredentials);
                    }

                    if(preAuthorizedCodeOnChain)
                    {
                        grantTypes.Add(OAuthRequestParameterValues.GrantTypePreAuthorizedCode);
                    }

                    AppendStringArrayField(
                        sb,
                        AuthorizationServerMetadataParameterNames.GrantTypesSupported,
                        grantTypes);
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
                        true);
                }

                //authorization_details_types_supported (RFC 9396 §10). Advertised when a
                //token grant that can process authorization_details is on the chain AND the
                //decision seam that mints the OID4VCI §6.2 credential_identifiers is wired —
                //an advertisement without the seam would invite requests the server refuses
                //with invalid_authorization_details.
                if((authorizationCodeOnChain || preAuthorizedCodeOnChain)
                    && oauth.ResolveCredentialAuthorizationAsync is not null)
                {
                    AppendStringArrayField(
                        sb,
                        AuthorizationServerMetadataParameterNames.AuthorizationDetailsTypesSupported,
                        oauth.AuthorizationDetailTypes.RegisteredTypes);
                }

                //JARM §4: advertise the JWT-secured response modes and signing algorithms
                //when the authorize endpoint is on the chain AND this registration carries
                //an authorization-response signing key — an advertisement without the key
                //would invite response_mode requests the server refuses with invalid_request.
                if(authorizationCodeOnChain)
                {
                    IReadOnlyList<string> jarmAlgs = await ResolveSigningAlgValuesAsync(
                        Verifiable.Cryptography.Context.KeyUsageContext.AuthorizationResponseSigning,
                        server, registration, context, ct).ConfigureAwait(false);
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
                            ]);
                        AppendStringArrayField(
                            sb,
                            Jarm.JarmServerMetadataParameterNames.AuthorizationSigningAlgValuesSupported,
                            jarmAlgs);
                    }
                }

                //RFC 9701 §7: advertise the introspection-response signing algorithms when
                //the introspection endpoint is on the chain AND this registration carries
                //an introspection-response signing key — an advertisement without the key
                //would invite Accept: application/token-introspection+jwt requests the
                //server refuses with invalid_request.
                if(introspectionOnChain)
                {
                    IReadOnlyList<string> introspectionAlgs = await ResolveSigningAlgValuesAsync(
                        Verifiable.Cryptography.Context.KeyUsageContext.IntrospectionResponseSigning,
                        server, registration, context, ct).ConfigureAwait(false);
                    if(introspectionAlgs.Count > 0)
                    {
                        AppendStringArrayField(
                            sb,
                            Introspection.IntrospectionServerMetadataParameterNames.IntrospectionSigningAlgValuesSupported,
                            introspectionAlgs);
                    }
                }

                //code_challenge_methods_supported (RFC 7636 §6.2.1). The
                //library only implements S256 — plain is forbidden per OAuth
                //2.1 §7.5.1.
                if(authorizationCodeOnChain)
                {
                    AppendStringArrayField(
                        sb,
                        AuthorizationServerMetadataParameterNames.CodeChallengeMethodsSupported,
                        CodeChallengeMethodS256);

                    //FAPI 2.0 §5.2.2 / RFC 9207: advertise whether PAR is mandatory and
                    //whether the iss authorization-response parameter is emitted. Both
                    //come from the resolved policy so the advertisement matches enforcement.
                    AppendBooleanField(
                        sb,
                        AuthorizationServerMetadataParameterNames.RequirePushedAuthorizationRequests,
                        context.RequirePushedAuthorizationRequests);
                    AppendBooleanField(
                        sb,
                        AuthorizationServerMetadataParameterNames.AuthorizationResponseIssParameterSupported,
                        context.EmitIssOnRedirect);
                }

                //RFC 9449 §5.1 — advertise the DPoP proof signature algorithms the AS
                //accepts whenever DPoP validation is wired (FAPI 2.0 sender-constrained
                //tokens). Independent of the authorize-endpoint chain.
                if(oauth.ValidateDpopProofAsync is not null)
                {
                    AppendStringArrayField(
                        sb,
                        AuthorizationServerMetadataParameterNames.DpopSigningAlgValuesSupported,
                        WellKnownDpopValues.SupportedSigningAlgorithms);
                }

                //OIDC Back-Channel Logout 1.0 §4: advertise back-channel logout only when the
                //capability is allowed AND the fan-out seam is wired (fail-closed). The OP is
                //the sender — there is no OP endpoint to chain — so the boolean flags are
                //emitted here rather than via a candidate's DiscoveryMetadataKey. The OP
                //includes a sid in its Logout Tokens (the per-session sid), so session-based
                //back-channel logout is supported too.
                if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OidcBackChannelLogout)
                    && oauth.DeliverBackChannelLogoutAsync is not null)
                {
                    AppendBooleanField(
                        sb,
                        AuthorizationServerMetadataParameterNames.BackchannelLogoutSupported,
                        true);
                    AppendBooleanField(
                        sb,
                        AuthorizationServerMetadataParameterNames.BackchannelLogoutSessionSupported,
                        true);
                }

                //token_endpoint_auth_methods_supported (RFC 8414 §2 OPTIONAL).
                //The library's token endpoint accepts PKCE-only public clients
                //per OAuth 2.1 — auth method "none". Deployments that add
                //client_secret_basic / private_key_jwt / mTLS auth advertise
                //those via ContributeDiscoveryFieldsAsync; the library default
                //reflects what the token endpoint code actually accepts today.
                if(tokenEndpointOnChain)
                {
                    AppendStringArrayField(
                        sb,
                        AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported,
                        TokenEndpointAuthMethodNone);
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
                        sortedScopes);
                }

                //claims_supported (OIDC Discovery §3 RECOMMENDED). Lists the
                //JWT claim names the standard
                //ContributionProfiles.StandardClaimIssuer rules can emit, plus
                //the spec-required sub. The list is aspirational per OIDC
                //Discovery §3 — the OP is not guaranteed to populate every
                //advertised claim for every request; scope / authentication-
                //context drives actual emission. Deployments that install
                //custom contributors extend the list via
                //ContributeDiscoveryFieldsAsync; the library default reflects
                //what the standard rules emit. Gated on authorization_code
                //chain presence because the field is OIDC-specific.
                if(authorizationCodeOnChain)
                {
                    AppendStringArrayField(
                        sb,
                        OpenIdProviderMetadataParameterNames.ClaimsSupported,
                        StandardClaimsSupported);

                    //claim_types_supported (OIDC Core §5.6 / OIDC Discovery §3
                    //OPTIONAL). The library supplies claim values directly
                    //(normal claim type per §5.6.1); aggregated and distributed
                    //claim types are not implemented. Default per OIDC
                    //Discovery §3 is ["normal"] when the field is absent;
                    //emitting it explicitly is the unambiguous form.
                    AppendStringArrayField(
                        sb,
                        OpenIdProviderMetadataParameterNames.ClaimTypesSupported,
                        ClaimTypeNormal);
                }

                //Application-supplied additional fields merged after the base set.
                if(oauth.ContributeDiscoveryFieldsAsync is not null)
                {
                    DiscoveryDocumentContribution contributed =
                        await oauth.ContributeDiscoveryFieldsAsync(
                            registration, context, ct).ConfigureAwait(false);

                    foreach(DiscoveryField field in contributed.Fields)
                    {
                        AppendContributedField(sb, field);
                    }
                }

                sb.Append('}');

                string discoveryJson = sb.ToString();
                JsonAppender.Return(sb);
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
    private static void AppendField(StringBuilder sb, string key, string value)
    {
        //Discovery callers always emit issuer first, so subsequent fields
        //carry a leading comma. Threading first=false into JsonAppender
        //preserves that contract while routing escape through the shared
        //primitive.
        bool first = false;
        JsonAppender.AppendStringField(sb, key, value, ref first);
    }


    /// <summary>
    /// Appends a string-array field to the discovery-document builder,
    /// formatted as <c>,"key":["v1","v2",…]</c>. Always emits the leading
    /// comma; callers must have written the opening brace and at least the
    /// <c>issuer</c> field before calling. No-ops on an empty list to avoid
    /// emitting <c>"key":[]</c> for fields that should be omitted entirely
    /// when no values are available.
    /// </summary>
    private static void AppendStringArrayField(
        StringBuilder sb, string key, IReadOnlyList<string> values)
    {
        if(values.Count == 0) { return; }

        bool first = false;
        JsonAppender.AppendStringArrayField(sb, key, values, ref first);
    }


    /// <summary>
    /// Appends a boolean field to the discovery-document builder, formatted as
    /// <c>,"key":true|false</c>. Always emits the leading comma; callers must have
    /// written the opening brace and at least the <c>issuer</c> field first.
    /// </summary>
    private static void AppendBooleanField(StringBuilder sb, string key, bool value)
    {
        bool first = false;
        JsonAppender.AppendBoolField(sb, key, value, ref first);
    }


    //Static well-known value sets emitted by the discovery endpoint.
    private static readonly IReadOnlyList<string> SubjectTypePublic = ["public"];
    private static readonly IReadOnlyList<string> ResponseTypeCode = ["code"];
    private static readonly IReadOnlyList<string> CodeChallengeMethodS256 = ["S256"];
    private static readonly IReadOnlyList<string> TokenEndpointAuthMethodNone = ["none"];
    private static readonly IReadOnlyList<string> ClaimTypeNormal = ["normal"];

    /// <summary>
    /// JWT claim names the standard
    /// <see cref="ContributionProfiles.StandardClaimIssuer"/> rules can emit,
    /// plus the spec-required <c>sub</c>. Sorted ordinally for deterministic
    /// wire output. Synchronisation invariant: every name added to or removed
    /// from the standard contributors (chunks 4a / 4b / 5) must update this
    /// list. The <see cref="ContributorChainRegressionTests"/> baseline pins
    /// the contributor output; this list pins the wire advertisement.
    /// </summary>
    private static readonly IReadOnlyList<string> StandardClaimsSupported =
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
    /// Derives <c>id_token_signing_alg_values_supported</c> from the
    /// registration's <see cref="KeyUsageContext.IdTokenIssuance"/> signing
    /// keys. Each <see cref="KeyId"/> in the rotation-aware
    /// <see cref="SigningKeySet"/> is resolved through the verification-key
    /// resolver and its <see cref="PublicKeyMemory.Tag"/> mapped to a JWA
    /// identifier via <see cref="CryptoFormatConversions.DefaultTagToJwaConverter"/>.
    /// The set is deduplicated by ordinal equality and stable across the
    /// rotation-slot order.
    /// </summary>
    /// <remarks>
    /// Returns an empty list when the registration has no IdTokenIssuance
    /// signing keys configured (the OIDC ID Token producer would not run for
    /// such a registration anyway). The discovery emitter omits the field
    /// entirely in that case rather than emitting an empty array.
    /// </remarks>
    private static async ValueTask<IReadOnlyList<string>> ResolveSigningAlgValuesAsync(
        Verifiable.Cryptography.Context.KeyUsageContext usage,
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        if(!((ClientRecord)registration).SigningKeys.TryGetValue(usage, out SigningKeySet? signingKeySet))
        {
            return [];
        }

        ServerVerificationKeyResolverDelegate? resolver =
            oauth.Cryptography.VerificationKeyResolver;
        if(resolver is null)
        {
            return [];
        }

        HashSet<string> algorithms = new(StringComparer.Ordinal);
        foreach(KeyId keyId in signingKeySet.Current)
        {
            Verifiable.Cryptography.PublicKeyMemory? key =
                await resolver(keyId, registration.TenantId, context, cancellationToken)
                    .ConfigureAwait(false);
            if(key is null) { continue; }

            string jwa = Verifiable.JCose.CryptoFormatConversions.DefaultTagToJwaConverter(key.Tag);
            algorithms.Add(jwa);
        }

        return algorithms.Count == 0 ? [] : algorithms.ToArray();
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
        bool first = false;
        switch(field)
        {
            case DiscoveryStringField stringField:
                JsonAppender.AppendStringField(sb, field.Name, stringField.Value, ref first);
                return;

            case DiscoveryBooleanField booleanField:
                JsonAppender.AppendBoolField(sb, field.Name, booleanField.Value, ref first);
                return;

            case DiscoveryNumberField numberField:
                JsonAppender.AppendInt64Field(sb, field.Name, numberField.Value, ref first);
                return;

            case DiscoveryStringArrayField arrayField:
                JsonAppender.AppendStringArrayField(sb, field.Name, arrayField.Values, ref first);
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
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append("{\"keys\":[");

            bool first = true;
            foreach(JsonWebKey key in jwks.Keys)
            {
                if(!first)
                {
                    sb.Append(',');
                }

                first = false;
                JsonAppender.AppendObject(sb, key);
            }

            sb.Append("]}");

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
