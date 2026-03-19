using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode.Server;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Oid4Vp;

using Verifiable.OAuth.Server;

using Verifiable.OAuth.Server.Audit;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Routing;
namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Endpoint builder module for the OAuth 2.0 Authorization Code flow with PKCE.
/// </summary>
/// <remarks>
/// <para>
/// Produces PAR, Authorize (PAR-backed), Direct Authorize, and Token endpoints.
/// Register at startup via <see cref="AuthorizationServer.EndpointBuilders"/>:
/// </para>
/// <code>
/// server.EndpointBuilders.AddRange([
///     AuthCodeEndpoints.Builder,
///     MetadataEndpoints.Builder
/// ]);
/// </code>
/// <para>
/// <strong>JSON wire format and the serialization firewall.</strong> The
/// HTTP response bodies this module emits — the PAR response and the token
/// response — are written as JSON by hand using
/// <see cref="System.Text.StringBuilder"/> rather than through a serializer.
/// This is deliberate. <c>Verifiable.OAuth</c> takes no dependency on
/// <c>Verifiable.Json</c>, on <c>System.Text.Json</c>, or on any other JSON
/// library, and the project's banned-symbol analyzer enforces this. The
/// library does not impose a JSON implementation on the application.
/// </para>
/// <para>
/// The wire shapes here are RFC-defined and stable: a handful of well-known
/// field names per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>
/// for the token response and
/// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>
/// for the PAR response, all primitive values (strings, integers), no
/// nested or schema-variable structure. For shapes like that, manual
/// <see cref="System.Text.StringBuilder"/> construction is the simplest
/// path that respects the firewall and stays AOT-safe without
/// source-generator context maintenance.
/// </para>
/// <para>
/// The corresponding parsing direction lives behind delegate slots so the
/// application chooses the parser; default implementations live in
/// <c>Verifiable.Json</c> and a CBOR-speaking or otherwise custom
/// deployment supplies its own. The output side stays symmetric: a
/// non-JSON-format deployment that needs to swap the response-building
/// surface replaces these endpoint builders with its own. The library
/// remains agnostic to wire format.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthCodeEndpoints")]
public static class AuthCodeEndpoints
{
    private const string Get = "GET";
    private const string Post = "POST";

    //SHA-256 is the only digest algorithm OAuth 2.0 PKCE per RFC 7636 §4.2 and
    //the Authorization Code grant code-hash currently use. The tag is pre-built
    //here to keep call sites a single line; if a future profile needs SHA-384
    //or post-quantum digests, lift this static into a per-call argument and
    //pass the algorithm-appropriate length from
    //<see cref="WellKnownHashAlgorithms.GetSizeBytes(HashAlgorithmName)"/>.
    private static readonly Tag Sha256DigestTag = new(new Dictionary<Type, object>
    {
        [typeof(HashAlgorithmName)] = HashAlgorithmName.SHA256,
        [typeof(Purpose)] = Purpose.Digest
    });


    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="AuthorizationServer.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, server) =>
    {
        List<ServerEndpoint> endpoints = [];

        if(registration.IsCapabilityAllowed(ServerCapabilityName.PushedAuthorization))
        {
            endpoints.Add(BuildPar());
        }

        if(registration.IsCapabilityAllowed(ServerCapabilityName.AuthorizationCode))
        {
            endpoints.Add(BuildAuthorize());
        }

        if(registration.IsCapabilityAllowed(ServerCapabilityName.DirectAuthorization))
        {
            endpoints.Add(BuildDirectAuthorize());
        }

        bool hasTokenCapability =
            registration.IsCapabilityAllowed(ServerCapabilityName.AuthorizationCode) ||
            registration.IsCapabilityAllowed(ServerCapabilityName.ClientCredentials) ||
            registration.IsCapabilityAllowed(ServerCapabilityName.TokenExchange);

        if(hasTokenCapability)
        {
            endpoints.Add(BuildToken());
        }

        if(registration.IsCapabilityAllowed(ServerCapabilityName.TokenRevocation))
        {
            endpoints.Add(BuildRevocation());
        }

        if(registration.IsCapabilityAllowed(ServerCapabilityName.TokenIntrospection))
        {
            endpoints.Add(BuildIntrospection());
        }

        return endpoints;
    };


    /// <summary>
    /// Builds the PAR endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>.
    /// </summary>
    /// <remarks>
    /// <see cref="ServerEndpoint.BuildResponse"/> writes the response body —
    /// <c>request_uri</c> and <c>expires_in</c> — directly with
    /// <see cref="System.Text.StringBuilder"/>. See the serialization-firewall
    /// paragraph in the remarks on <see cref="AuthCodeEndpoints"/> for the
    /// rationale.
    /// </remarks>
    private static ServerEndpoint BuildPar() =>
        new()
        {
            Name = "AuthCode.Par",
            HttpMethod = Post,
            Capability = ServerCapabilityName.PushedAuthorization,
            StartsNewFlow = true,
            Kind = FlowKind.AuthCodeServer,

            //Acceptance test: POST to /par for this registration with the
            //PKCE PAR signature in the body (code_challenge + redirect_uri,
            //no request JAR parameter). Disjointness vs OID4VP PAR: PKCE PAR
            //is wire-driven (body fields), OID4VP PAR is context-driven
            //(TransactionNonce on context). The TransactionNonce-absent check
            //below is belt-and-braces — under correct application setup the
            //two never collide, but the explicit negative check makes the
            //disjointness assertion in DEBUG builds catch any deployment
            //bug where the verifier code path leaks context state into a
            //PKCE PAR request.
            MatchesRequest = static (fields, context, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!string.Equals(req.Method, Post, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRegistration? registration = context.Registration;
                if(registration is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!registration.IsCapabilityAllowed(ServerCapabilityName.PushedAuthorization))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!ServerPaths.IsEndpoint(req.Path, ServerEndpointPaths.Par, registration.TenantId.Value))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!fields.ContainsKey(OAuthRequestParameters.CodeChallenge))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                //Disjointness vs OID4VP PAR — see remarks above.
                if(context.TransactionNonce is not null)
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static (fields, context, currentState, server, ct) =>
            {
                if(!fields.TryGetValue(OAuthRequestParameters.ClientId, out string? clientId)
                    || string.IsNullOrWhiteSpace(clientId))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing client_id.")));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.CodeChallenge, out string? challenge)
                    || string.IsNullOrWhiteSpace(challenge))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing code_challenge.")));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.CodeChallengeMethod, out string? method)
                    || !string.Equals(method, OAuthRequestParameters.CodeChallengeMethodS256,
                        StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "code_challenge_method must be S256.")));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.RedirectUri, out string? redirectUriString)
                    || !Uri.TryCreate(redirectUriString, UriKind.Absolute, out Uri? redirectUri))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing or invalid redirect_uri.")));
                }

                fields.TryGetValue(OAuthRequestParameters.Scope, out string? scope);
                scope ??= string.Empty;

                fields.TryGetValue(WellKnownJwtClaims.Nonce, out string? nonce);
                nonce ??= string.Empty;

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                string flowId = context.FlowId!;
                string requestUriToken = Guid.NewGuid().ToString("N");
                Uri requestUri = new($"urn:ietf:params:oauth:request_uri:{requestUriToken}");

                //RFC 9126 §2.2 leaves the request_uri lifetime implementation-defined.
                //Library policy lives in TimingPolicy.AuthCodeParLifetime.
                TimeSpan parLifetime = server.Timings.AuthCodeParLifetime;
                DateTimeOffset expiresAt = now + parLifetime;
                int expiresIn = (int)parLifetime.TotalSeconds;

                return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>(
                    (new ServerParValidated(
                        FlowId: flowId,
                        RequestUri: requestUri,
                        CodeChallenge: challenge,
                        RedirectUri: redirectUri,
                        Scope: scope,
                        ClientId: clientId,
                        Nonce: nonce,
                        ExpectedIssuer: clientId,
                        ReceivedAt: now,
                        ExpiresAt: expiresAt,
                        ExpiresIn: expiresIn), null));
            },
            BuildResponse = static (state, _, _) =>
            {
                if(state is not ParRequestReceivedState par)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after PAR.");
                }

                //ExpiresIn is the wire value preserved from PAR-input time so the
                //response value is exactly what the client was promised at PAR
                //receipt, with no recomputation drift between BuildInputAsync and
                //BuildResponse. The source policy is TimingPolicy.AuthCodeParLifetime.
                string body =
                    $"{{\"request_uri\":\"{par.RequestUri}\",\"expires_in\":{par.ExpiresIn}}}";
                return ServerHttpResponse.Ok(body, "application/json");
            }
        };


    private static ServerEndpoint BuildAuthorize() =>
        new()
        {
            Name = "AuthCode.Authorize",
            HttpMethod = Get,
            Capability = ServerCapabilityName.AuthorizationCode,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,

            ExtractCorrelationKey = static (path, fields, context) =>
            {
                if(fields.TryGetValue(OAuthRequestParameters.RequestUri, out string? requestUri)
                    && !string.IsNullOrWhiteSpace(requestUri))
                {
                    const string urnPrefix = "urn:ietf:params:oauth:request_uri:";
                    return requestUri.StartsWith(urnPrefix, StringComparison.Ordinal)
                        ? requestUri[urnPrefix.Length..]
                        : requestUri;
                }

                return null;
            },

            //Acceptance test: GET to /authorize for this registration with a
            //request_uri query parameter. The request_uri presence is what
            //distinguishes the PAR-completed Authorize from the direct
            //Authorize (PKCE in query string) which has the inverse signature.
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
                if(!registration.IsCapabilityAllowed(ServerCapabilityName.AuthorizationCode))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!ServerPaths.IsEndpoint(req.Path, ServerEndpointPaths.Authorize, registration.TenantId.Value))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!fields.ContainsKey(OAuthRequestParameters.RequestUri))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static (fields, context, currentState, server, ct) =>
            {
                if(currentState is not ParRequestReceivedState)
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Flow not in expected state.")));
                }

                string? subjectId = context.SubjectId;
                if(string.IsNullOrWhiteSpace(subjectId))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError, "Subject not authenticated.")));
                }

                DateTimeOffset authTime = context.AuthTime ?? server.TimeProvider.GetUtcNow();

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                string rawCode = Guid.NewGuid().ToString("N");
                string codeHash = ComputeDigestBase64Url(
                    rawCode,
                    Sha256DigestTag,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    server.Codecs.ComputeDigest!,
                    server.Codecs.Encoder!,
                    SensitiveMemoryPool<byte>.Shared);

                ParRequestReceivedState parState = (ParRequestReceivedState)currentState;

                fields.TryGetValue(OAuthRequestParameters.Scope, out string? scope);

                OAuthFlowInput input = new ServerAuthorizeCompleted(
                    CodeHash: codeHash,
                    SubjectId: subjectId,
                    AuthTime: authTime,
                    Scope: scope ?? parState.Scope,
                    CompletedAt: now);

                return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((input, null));
            },
            BuildResponse = static (state, _, context) =>
            {
                if(state is not ServerCodeIssuedState code)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after authorize.");
                }

                string location =
                    $"{code.RedirectUri}?code={Uri.EscapeDataString(code.CodeHash)}";
                return ServerHttpResponse.Redirect(location);
            }
        };


    private static ServerEndpoint BuildDirectAuthorize() =>
        new()
        {
            Name = "AuthCode.DirectAuthorize",
            HttpMethod = Get,
            Capability = ServerCapabilityName.DirectAuthorization,
            StartsNewFlow = true,
            Kind = FlowKind.AuthCodeServer,

            //Acceptance test: GET to /authorize for this registration with
            //code_challenge in the query (direct PKCE) and no request_uri.
            //The request_uri-absence check is what distinguishes this matcher
            //from the PAR-completed Authorize at the same path-and-method;
            //the disjointness assertion in DEBUG builds catches any drift.
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
                if(!registration.IsCapabilityAllowed(ServerCapabilityName.DirectAuthorization))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!ServerPaths.IsEndpoint(req.Path, ServerEndpointPaths.Authorize, registration.TenantId.Value))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(fields.ContainsKey(OAuthRequestParameters.RequestUri))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!fields.ContainsKey(OAuthRequestParameters.CodeChallenge))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static (fields, context, currentState, server, ct) =>
            {
                if(!fields.TryGetValue(OAuthRequestParameters.ClientId, out string? clientId)
                    || string.IsNullOrWhiteSpace(clientId))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing client_id.")));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.CodeChallenge, out string? challenge)
                    || string.IsNullOrWhiteSpace(challenge))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing code_challenge.")));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.CodeChallengeMethod, out string? method)
                    || !string.Equals(method, OAuthRequestParameters.CodeChallengeMethodS256,
                        StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "code_challenge_method must be S256.")));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.RedirectUri, out string? redirectUriString)
                    || !Uri.TryCreate(redirectUriString, UriKind.Absolute, out Uri? redirectUri))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing or invalid redirect_uri.")));
                }

                string? subjectId = context.SubjectId;
                if(string.IsNullOrWhiteSpace(subjectId))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError, "Subject not authenticated.")));
                }

                fields.TryGetValue(OAuthRequestParameters.Scope, out string? scope);
                scope ??= string.Empty;

                fields.TryGetValue(WellKnownJwtClaims.Nonce, out string? nonce);
                nonce ??= string.Empty;

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                string flowId = context.FlowId!;

                //RFC 6749 §4.1.2 recommends a maximum of 10 minutes for
                //authorization codes. Library policy lives in
                //TimingPolicy.AuthorizationCodeLifetime.
                DateTimeOffset expiresAt = now + server.Timings.AuthorizationCodeLifetime;

                string rawCode = Guid.NewGuid().ToString("N");
                string codeHash = ComputeDigestBase64Url(
                    rawCode,
                    Sha256DigestTag,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    server.Codecs.ComputeDigest!,
                    server.Codecs.Encoder!,
                    SensitiveMemoryPool<byte>.Shared);

                return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>(
                    (new ServerDirectAuthorizeCompleted(
                        FlowId: flowId,
                        CodeHash: codeHash,
                        CodeChallenge: challenge,
                        RedirectUri: redirectUri,
                        Scope: scope,
                        ClientId: clientId,
                        Nonce: nonce,
                        SubjectId: subjectId,
                        AuthTime: now,
                        ExpectedIssuer: clientId,
                        CompletedAt: now,
                        ExpiresAt: expiresAt), null));
            },

            BuildResponse = static (state, _, context) =>
            {
                if(state is not ServerCodeIssuedState code)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after direct authorize.");
                }

                string location =
                    $"{code.RedirectUri}?code={Uri.EscapeDataString(code.CodeHash)}";
                return ServerHttpResponse.Redirect(location);
            }
        };


    /// <summary>
    /// Default producer list when
    /// <see cref="ServerConfiguration.TokenProducers"/> is empty. Single producer
    /// matches the library's historical access-token-only response shape.
    /// </summary>
    private static readonly IReadOnlyList<TokenProducer> DefaultTokenProducers =
        [TokenProducer.Rfc9068AccessToken];


    /// <summary>
    /// Builds the Token endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    /// <remarks>
    /// <see cref="ServerEndpoint.BuildResponse"/> writes the response body —
    /// <c>access_token</c>, <c>token_type</c>, <c>expires_in</c>, and the
    /// optional <c>id_token</c>, <c>refresh_token</c>, and <c>scope</c>
    /// fields — directly with <see cref="System.Text.StringBuilder"/>. See
    /// the serialization-firewall paragraph in the remarks on
    /// <see cref="AuthCodeEndpoints"/> for the rationale.
    /// </remarks>
    private static ServerEndpoint BuildToken() =>
        new()
        {
            Name = "AuthCode.Token",
            HttpMethod = Post,
            Capability = ServerCapabilityName.AuthorizationCode,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,

            //Acceptance test: POST to /token for this registration with
            //grant_type=authorization_code and a code parameter. Other grants
            //(refresh_token, client_credentials) would arrive at the same
            //path but with different grant_type values and would route to
            //sibling matchers; this one is specific to the authorization_code
            //grant.
            MatchesRequest = static (fields, context, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!string.Equals(req.Method, Post, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRegistration? registration = context.Registration;
                if(registration is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!registration.IsCapabilityAllowed(ServerCapabilityName.AuthorizationCode))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!ServerPaths.IsEndpoint(req.Path, ServerEndpointPaths.Token, registration.TenantId.Value))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!fields.TryGetValue(OAuthRequestParameters.GrantType, out string? grantType)
                    || !string.Equals(grantType, OAuthRequestParameters.GrantTypeAuthorizationCode, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!fields.ContainsKey(OAuthRequestParameters.Code))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            ExtractCorrelationKey = static (path, fields, context) =>
                fields.TryGetValue(OAuthRequestParameters.Code, out string? code)
                    && !string.IsNullOrWhiteSpace(code) ? code : null,
            BuildInputAsync = static async (fields, context, currentState, server, ct) =>
            {
                if(currentState is not ServerCodeIssuedState codeState)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, "Flow not in expected state."));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.CodeVerifier, out string? verifier)
                    || string.IsNullOrWhiteSpace(verifier))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing code_verifier."));
                }

                string computedChallenge = ComputeDigestBase64Url(
                    verifier,
                    Sha256DigestTag,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    server.Codecs.ComputeDigest!,
                    server.Codecs.Encoder!,
                    SensitiveMemoryPool<byte>.Shared);
                if(!string.Equals(computedChallenge, codeState.CodeChallenge,
                    StringComparison.Ordinal))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, "PKCE verification failed."));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.ClientId, out string? clientId)
                    || !string.Equals(clientId, codeState.ClientId, StringComparison.Ordinal))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidGrant, "client_id mismatch."));
                }

                //The dispatcher already loaded the registration for this tenant onto
                //the context. Use that rather than re-loading by client_id; doing the
                //lookup again under a different identifier would conflate clientId
                //and tenantId, which the protocol layer keeps distinct.
                ClientRegistration? registration = context.Registration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Unknown client."));
                }

                Uri issuerUri;
                try
                {
                    issuerUri = server.Integration.ResolveIssuerAsync is not null
                        ? await server.Integration.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false)
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                IssuanceContext issuance = new()
                {
                    Registration = registration,
                    Context = context,
                    IssuerUri = issuerUri,
                    Subject = codeState.SubjectId,
                    Scope = codeState.Scope,
                    ClientId = codeState.ClientId,
                    IssuedAt = now,
                    Nonce = string.IsNullOrEmpty(codeState.Nonce) ? null : codeState.Nonce,
                    AuthTime = codeState.AuthTime
                };

                IReadOnlyList<TokenProducer> producers =
                    server.Configuration.TokenProducers.Count > 0 ? server.Configuration.TokenProducers : DefaultTokenProducers;

                IReadOnlyList<ClaimContributor> contributors = server.Configuration.ClaimContributors;

                Dictionary<string, string> issuedTokens = new(producers.Count);
                Dictionary<string, IssuedTokenAudit> issuedAudits = new(producers.Count);
                DateTimeOffset latestExpiry = now;

                foreach(TokenProducer producer in producers)
                {
                    if(!await server.CheckCapabilityAsync(
                        registration, producer.RequiredCapability, context, ct)
                        .ConfigureAwait(false))
                    {
                        continue;
                    }

                    if(!await producer.IsApplicable(issuance, ct).ConfigureAwait(false))
                    {
                        continue;
                    }

                    KeyId signingKeyId = await SigningKeySelection.ResolveSigningKeyIdAsync(
                        server, registration, producer.KeyUsage, context, ct)
                        .ConfigureAwait(false);

                    PrivateKeyMemory? signingKey = await server.Cryptography.SigningKeyResolver!(
                        signingKeyId.Value, context, ct).ConfigureAwait(false);

                    if(signingKey is null)
                    {
                        return (null, ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError,
                            $"Signing key unavailable for producer '{producer.Name}'."));
                    }

                    string algorithm =
                        CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

                    TokenProducerOutput output = await producer.BuildAsync(
                        issuance, server, signingKeyId, algorithm, ct).ConfigureAwait(false);

                    JwtPayload payload = output.Payload;

                    foreach(ClaimContributor contributor in contributors)
                    {
                        if(!await contributor.IsApplicable(issuance, producer, ct)
                            .ConfigureAwait(false))
                        {
                            continue;
                        }

                        ClaimContribution contributed =
                            await contributor.BuildAsync(issuance, producer, ct)
                                .ConfigureAwait(false);

                        foreach(ClaimEntry entry in contributed.Entries)
                        {
                            payload[entry.Name] = entry.Value;
                        }
                    }

                    UnsignedJwt unsigned = new(output.Header, payload);

                    using JwsMessage jws = await unsigned.SignAsync(
                        signingKey,
                        server.Codecs.JwtHeaderSerializer!,
                        server.Codecs.JwtPayloadSerializer!,
                        server.Codecs.Encoder!,
                        SensitiveMemoryPool<byte>.Shared,
                        ct).ConfigureAwait(false);

                    string compactJws = JwsSerialization.SerializeCompact(jws, server.Codecs.Encoder!);

                    issuedTokens[producer.ResponseField] = compactJws;

                    string jti = ExtractJti(payload);
                    DateTimeOffset issuedAt = ExtractInstant(payload, WellKnownJwtClaims.Iat, now);
                    DateTimeOffset expiresAt = ExtractInstant(payload, WellKnownJwtClaims.Exp, now);

                    issuedAudits[producer.ResponseField] = new IssuedTokenAudit
                    {
                        Jti = jti,
                        SigningKeyId = signingKeyId.Value,
                        IssuedAt = issuedAt,
                        ExpiresAt = expiresAt
                    };

                    if(expiresAt > latestExpiry)
                    {
                        latestExpiry = expiresAt;
                    }
                }

                if(issuedTokens.Count == 0)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "No applicable token producers."));
                }

                IssuedTokenSet tokenSet = new() { Tokens = issuedTokens };
                context.SetIssuedTokens(tokenSet);

                IssuedTokenAuditSet auditSet = new() { Audits = issuedAudits };

                return (new ServerTokenExchangeSucceeded(
                    IssuedTokens: auditSet,
                    IssuedAt: now,
                    ExpiresAt: latestExpiry), null);
            },
            BuildResponse = static (state, _, context) =>
            {
                if(state is not ServerTokenIssuedState issued)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after token exchange.");
                }

                IssuedTokenSet? tokenSet = context.IssuedTokens;
                if(tokenSet is null || tokenSet.AccessToken is null)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Issued tokens not found in context.");
                }

                IssuedTokenAudit? accessAudit = issued.IssuedTokens.AccessTokenAudit;
                if(accessAudit is null)
                {
                    //Structural invariant: the upstream check above already
                    //returned ServerError when tokenSet.AccessToken was null.
                    //Reaching here without an audit means the audit set was
                    //assembled out of sync with the tokens dictionary —
                    //library bug, not a runtime condition.
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Access token audit missing alongside an issued access token — library invariant violation.");
                }

                int expiresIn = (int)(accessAudit.ExpiresAt - accessAudit.IssuedAt).TotalSeconds;

                var sb = new StringBuilder();
                sb.Append("{\"access_token\":\"");
                sb.Append(tokenSet.AccessToken);
                sb.Append("\",\"token_type\":\"Bearer\",\"expires_in\":");
                sb.Append(expiresIn);

                if(tokenSet.IdToken is not null)
                {
                    sb.Append(",\"id_token\":\"");
                    sb.Append(tokenSet.IdToken);
                    sb.Append('"');
                }

                if(tokenSet.RefreshToken is not null)
                {
                    sb.Append(",\"refresh_token\":\"");
                    sb.Append(tokenSet.RefreshToken);
                    sb.Append('"');
                }

                if(!string.IsNullOrEmpty(issued.Scope))
                {
                    sb.Append(",\"scope\":\"");
                    sb.Append(issued.Scope);
                    sb.Append('"');
                }

                sb.Append('}');
                return ServerHttpResponse.Ok(sb.ToString(), "application/json");
            }
        };


    private static ServerEndpoint BuildRevocation() =>
        new()
        {
            Name = "AuthCode.Revocation",
            HttpMethod = Post,
            Capability = ServerCapabilityName.TokenRevocation,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,

            //Acceptance test: POST to /revoke for this registration with a
            //token body parameter per RFC 7009 §2.1.
            MatchesRequest = static (fields, context, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!string.Equals(req.Method, Post, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRegistration? registration = context.Registration;
                if(registration is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!registration.IsCapabilityAllowed(ServerCapabilityName.TokenRevocation))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!ServerPaths.IsEndpoint(req.Path, ServerEndpointPaths.Revoke, registration.TenantId.Value))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!fields.ContainsKey(OAuthRequestParameters.Token))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static (fields, context, currentState, server, ct) =>
                ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>(
                    (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Revocation not yet implemented."))),
            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static ServerEndpoint BuildIntrospection() =>
        new()
        {
            Name = "AuthCode.Introspection",
            HttpMethod = Post,
            Capability = ServerCapabilityName.TokenIntrospection,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,

            //Acceptance test: POST to /introspect for this registration with
            //a token body parameter per RFC 7662 §2.1.
            MatchesRequest = static (fields, context, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!string.Equals(req.Method, Post, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRegistration? registration = context.Registration;
                if(registration is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!registration.IsCapabilityAllowed(ServerCapabilityName.TokenIntrospection))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!ServerPaths.IsEndpoint(req.Path, ServerEndpointPaths.Introspect, registration.TenantId.Value))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!fields.ContainsKey(OAuthRequestParameters.Token))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static (fields, context, currentState, server, ct) =>
                ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>(
                    (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Introspection not yet implemented."))),
            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Hashes <paramref name="input"/> as ASCII bytes and returns the digest
    /// base64url-encoded. Used for PKCE S256 challenge recomputation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>
    /// and for authorization-code hashing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both the input bytes and the digest output are pool-allocated; nothing
    /// crosses the boundary as a managed array. The algorithm is carried in
    /// <paramref name="algorithmTag"/>; the same helper handles SHA-256 (RFC 7636
    /// §4.2 PKCE), SHA-384, SHA-512, or future post-quantum hashes without
    /// signature changes.
    /// </para>
    /// <para>
    /// The <see cref="CryptoEvent"/> the digest delegate emits is dropped here
    /// because the helper's two call contexts — code-hash storage and PKCE
    /// verification — already produce flow-level events through the AS pipeline.
    /// A separate digest event would duplicate that audit trail.
    /// </para>
    /// </remarks>
    internal static string ComputeDigestBase64Url(
        string input,
        Tag algorithmTag,
        int digestByteLength,
        ComputeDigestDelegate computeDigest,
        EncodeDelegate encoder,
        MemoryPool<byte> pool)
    {
        int inputByteCount = System.Text.Encoding.ASCII.GetByteCount(input);
        using IMemoryOwner<byte> inputOwner = pool.Rent(inputByteCount);
        Span<byte> inputBytes = inputOwner.Memory.Span[..inputByteCount];
        System.Text.Encoding.ASCII.GetBytes(input, inputBytes);

        (DigestValue digest, _) = computeDigest(
            inputBytes, digestByteLength, algorithmTag, pool);

        using(digest)
        {
            return encoder(digest.AsReadOnlySpan());
        }
    }


    private static string ExtractJti(JwtPayload payload)
    {
        if(payload.TryGetValue(WellKnownJwtClaims.Jti, out object? value) && value is string jti)
        {
            return jti;
        }

        //A producer that does not set jti is a library bug; return an empty
        //value rather than throwing so the request still succeeds. The audit
        //record will carry an empty string and the absence is observable.
        return string.Empty;
    }


    private static DateTimeOffset ExtractInstant(JwtPayload payload, string claim, DateTimeOffset fallback)
    {
        if(!payload.TryGetValue(claim, out object? value))
        {
            return fallback;
        }

        return value switch
        {
            long unixSeconds => DateTimeOffset.FromUnixTimeSeconds(unixSeconds),
            int unixSecondsInt => DateTimeOffset.FromUnixTimeSeconds(unixSecondsInt),
            DateTimeOffset dt => dt,
            _ => fallback
        };
    }
}
