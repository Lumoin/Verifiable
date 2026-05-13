using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode.Server;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Validation;

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

        if(registration.IsCapabilityAllowed(ServerCapabilityName.PushedAuthorization)
            && registration.IsCapabilityAllowed(ServerCapabilityName.JwtSecuredAuthorizationRequest))
        {
            endpoints.Add(BuildJarPar());
        }

        if(registration.IsCapabilityAllowed(ServerCapabilityName.DirectAuthorization)
            && registration.IsCapabilityAllowed(ServerCapabilityName.JwtSecuredAuthorizationRequest))
        {
            endpoints.Add(BuildAuthorizeJarByValue());
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
            HttpMethod = WellKnownHttpMethods.Post,
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
                if(!WellKnownHttpMethods.IsPost(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRecord? registration = context.Registration;
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

                //Disjointness vs JAR-PAR — a body carrying a 'request' parameter
                //routes to BuildJarPar regardless of any code_challenge/code_challenge_method
                //the client also (incorrectly) included. RFC 9101 §6.1 requires
                //outer parameters to be ignored when the JAR is present.
                if(fields.ContainsKey(OAuthRequestParameters.Request))
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

                fields.TryGetValue(OAuthRequestParameters.CodeChallengeMethod, out string? method);
                if(!IsAcceptedPkceMethod(method, context))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "code_challenge_method is not accepted under the active policy.")));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.RedirectUri, out string? redirectUriString)
                    || !Uri.TryCreate(redirectUriString, UriKind.Absolute, out Uri? redirectUri))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest, "Missing or invalid redirect_uri.")));
                }

                fields.TryGetValue(OAuthRequestParameters.Scope, out string? scope);
                if(context.ScopeRequiredOnRequest && string.IsNullOrEmpty(scope))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "scope is required under the active policy.")));
                }
                scope ??= string.Empty;

                fields.TryGetValue(WellKnownJwtClaims.Nonce, out string? nonce);
                nonce ??= string.Empty;

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                string flowId = context.FlowId!;
                string requestUriToken = Guid.NewGuid().ToString("N");
                Uri requestUri = new($"urn:ietf:params:oauth:request_uri:{requestUriToken}");

                //RFC 9126 §2.2 leaves the request_uri lifetime implementation-defined.
                //Library policy lives in policy.RequestUriLifetime (default 60s).
                TimeSpan parLifetime = context.RequestUriLifetime;
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
                return ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json);
            }
        };


    private static ServerEndpoint BuildAuthorize() =>
        new()
        {
            Name = "AuthCode.Authorize",
            HttpMethod = WellKnownHttpMethods.Get,
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
                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRecord? registration = context.Registration;
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
                    CryptoTags.Sha256Digest,
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

                return BuildAuthorizeRedirect(code, context);
            }
        };


    private static ServerEndpoint BuildDirectAuthorize() =>
        new()
        {
            Name = "AuthCode.DirectAuthorize",
            HttpMethod = WellKnownHttpMethods.Get,
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
                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRecord? registration = context.Registration;
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

                //Disjointness vs JAR-by-value Authorize — a query carrying a
                //'request' parameter routes to BuildAuthorizeJarByValue.
                if(fields.ContainsKey(OAuthRequestParameters.Request))
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

                fields.TryGetValue(OAuthRequestParameters.CodeChallengeMethod, out string? method);
                if(!IsAcceptedPkceMethod(method, context))
                {
                    return ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>((null,
                        ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "code_challenge_method is not accepted under the active policy.")));
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
                //policy.AuthorizationCodeLifetime (default 600s).
                DateTimeOffset expiresAt = now + context.AuthorizationCodeLifetime;

                string rawCode = Guid.NewGuid().ToString("N");
                string codeHash = ComputeDigestBase64Url(
                    rawCode,
                    CryptoTags.Sha256Digest,
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

                return BuildAuthorizeRedirect(code, context);
            }
        };


    /// <summary>
    /// Builds the JAR-PAR endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see> +
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>:
    /// PAR with a signed Request Object (JAR) instead of bare PKCE fields.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Disjoint from <see cref="BuildPar"/> on a single body-field signal —
    /// presence of the <c>request</c> parameter. The PKCE matcher's MatchesRequest
    /// rejects a body that carries <c>request</c>, the JAR matcher's MatchesRequest
    /// requires it; the chain remains disjoint and the DEBUG disjointness assertion
    /// passes.
    /// </para>
    /// </remarks>
    private static ServerEndpoint BuildJarPar() =>
        new()
        {
            Name = "AuthCode.JarPar",
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = ServerCapabilityName.PushedAuthorization,
            StartsNewFlow = true,
            Kind = FlowKind.AuthCodeServer,

            //Acceptance test: POST to /par for this registration with both PAR
            //and JAR capabilities allowed and the request body carrying a JAR
            //in the 'request' parameter.
            MatchesRequest = static (fields, context, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsPost(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRecord? registration = context.Registration;
                if(registration is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!registration.IsCapabilityAllowed(ServerCapabilityName.PushedAuthorization))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!registration.IsCapabilityAllowed(ServerCapabilityName.JwtSecuredAuthorizationRequest))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!ServerPaths.IsEndpoint(req.Path, ServerEndpointPaths.Par, registration.TenantId.Value))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!fields.ContainsKey(OAuthRequestParameters.Request))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, server, ct) =>
            {
                (AuthCodeRequestObject? requestObject, ServerHttpResponse? earlyExit) =
                    await VerifyAndValidateAuthCodeJarAsync(fields, context, server, ct)
                        .ConfigureAwait(false);

                if(earlyExit is not null)
                {
                    return ((OAuthFlowInput?)null, earlyExit);
                }

                AuthCodeRequestObject ro = requestObject!;
                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                string flowId = context.FlowId!;
                string requestUriToken = Guid.NewGuid().ToString("N");
                Uri requestUri = new($"urn:ietf:params:oauth:request_uri:{requestUriToken}");

                //RFC 9126 §2.2 leaves the request_uri lifetime implementation-defined.
                //Library policy lives in policy.RequestUriLifetime (default 60s).
                TimeSpan parLifetime = context.RequestUriLifetime;
                DateTimeOffset expiresAt = now + parLifetime;
                int expiresIn = (int)parLifetime.TotalSeconds;

                return ((OAuthFlowInput?)new ServerParValidated(
                    FlowId: flowId,
                    RequestUri: requestUri,
                    CodeChallenge: ro.CodeChallenge,
                    RedirectUri: ro.RedirectUri,
                    Scope: ro.Scope,
                    ClientId: ro.ClientId,
                    Nonce: ro.Nonce,
                    ExpectedIssuer: ro.ClientId,
                    ReceivedAt: now,
                    ExpiresAt: expiresAt,
                    ExpiresIn: expiresIn), null);
            },

            BuildResponse = static (state, _, _) =>
            {
                if(state is not ParRequestReceivedState par)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after JAR-PAR.");
                }

                string body =
                    $"{{\"request_uri\":\"{par.RequestUri}\",\"expires_in\":{par.ExpiresIn}}}";
                return ServerHttpResponse.Ok(body, WellKnownMediaTypes.Application.Json);
            }
        };


    /// <summary>
    /// Builds the JAR-by-value direct Authorize endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.1">RFC 9101 §6.1</see>:
    /// the authorize endpoint accepts a signed Request Object directly via the
    /// <c>request</c> query parameter without a prior PAR.
    /// </summary>
    /// <remarks>
    /// Disjoint from <see cref="BuildDirectAuthorize"/> and the PAR-completed
    /// <see cref="BuildAuthorize"/> on body/query signals — JAR-by-value matches
    /// when <c>request</c> is present and <c>request_uri</c> is absent; the
    /// PKCE direct matcher matches when neither <c>request</c> nor
    /// <c>request_uri</c> is present; the PAR-completed matcher matches when
    /// <c>request_uri</c> is present.
    /// </remarks>
    private static ServerEndpoint BuildAuthorizeJarByValue() =>
        new()
        {
            Name = "AuthCode.AuthorizeJarByValue",
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = ServerCapabilityName.DirectAuthorization,
            StartsNewFlow = true,
            Kind = FlowKind.AuthCodeServer,

            //Acceptance test: GET to /authorize for this registration with both
            //direct-authorize and JAR capabilities allowed, the query carrying a
            //JAR in the 'request' parameter, and no 'request_uri' (which would
            //route to BuildAuthorize per RFC 9101 §6.1).
            MatchesRequest = static (fields, context, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRecord? registration = context.Registration;
                if(registration is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!registration.IsCapabilityAllowed(ServerCapabilityName.DirectAuthorization))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!registration.IsCapabilityAllowed(ServerCapabilityName.JwtSecuredAuthorizationRequest))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!ServerPaths.IsEndpoint(req.Path, ServerEndpointPaths.Authorize, registration.TenantId.Value))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                //RFC 9101 §6.1 — request and request_uri MUST NOT both be present.
                //When both arrive, neither JAR matcher accepts; the request 404s
                //rather than silently picking one parameter over the other.
                if(fields.ContainsKey(OAuthRequestParameters.RequestUri))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                if(!fields.ContainsKey(OAuthRequestParameters.Request))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, server, ct) =>
            {
                (AuthCodeRequestObject? requestObject, ServerHttpResponse? earlyExit) =
                    await VerifyAndValidateAuthCodeJarAsync(fields, context, server, ct)
                        .ConfigureAwait(false);

                if(earlyExit is not null)
                {
                    return ((OAuthFlowInput?)null, earlyExit);
                }

                AuthCodeRequestObject ro = requestObject!;

                string? subjectId = context.SubjectId;
                if(string.IsNullOrWhiteSpace(subjectId))
                {
                    return ((OAuthFlowInput?)null,
                        ServerHttpResponse.ServerError(
                            OAuthErrors.ServerError, "Subject not authenticated."));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                string flowId = context.FlowId!;

                //RFC 6749 §4.1.2 recommends a maximum of 10 minutes for
                //authorization codes. Library policy lives in
                //policy.AuthorizationCodeLifetime (default 600s).
                DateTimeOffset expiresAt = now + context.AuthorizationCodeLifetime;

                string rawCode = Guid.NewGuid().ToString("N");
                string codeHash = ComputeDigestBase64Url(
                    rawCode,
                    CryptoTags.Sha256Digest,
                    WellKnownHashAlgorithms.Sha256SizeBytes,
                    server.Codecs.ComputeDigest!,
                    server.Codecs.Encoder!,
                    SensitiveMemoryPool<byte>.Shared);

                return ((OAuthFlowInput?)new ServerDirectAuthorizeCompleted(
                    FlowId: flowId,
                    CodeHash: codeHash,
                    CodeChallenge: ro.CodeChallenge,
                    RedirectUri: ro.RedirectUri,
                    Scope: ro.Scope,
                    ClientId: ro.ClientId,
                    Nonce: ro.Nonce,
                    SubjectId: subjectId,
                    AuthTime: now,
                    ExpectedIssuer: ro.ClientId,
                    CompletedAt: now,
                    ExpiresAt: expiresAt), null);
            },

            BuildResponse = static (state, _, context) =>
            {
                if(state is not ServerCodeIssuedState code)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Unexpected state after JAR-by-value direct authorize.");
                }

                return BuildAuthorizeRedirect(code, context);
            }
        };


    /// <summary>
    /// Shared validation pipeline for JAR-bearing AuthCode matchers (JAR-PAR and
    /// JAR-by-value direct Authorize). Verifies the JAR's signature, JOSE header,
    /// and timing claims via <see cref="JarVerification.VerifyAsync"/>; projects
    /// onto a typed <see cref="AuthCodeRequestObject"/>; runs the protocol-shaped
    /// claim checks RFC 9101 §10.2 and RFC 9700 §4 mandate; and validates the
    /// outer <c>client_id</c> against the JAR's per RFC 9700 §4.6 substitution
    /// defense.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Returns <c>(requestObject, null)</c> on success and <c>(null, response)</c>
    /// when validation fails. The matchers project the returned
    /// <see cref="AuthCodeRequestObject"/> onto their endpoint-specific input
    /// records (<see cref="ServerParValidated"/> for JAR-PAR;
    /// <see cref="ServerDirectAuthorizeCompleted"/> for JAR-by-value).
    /// </para>
    /// <para>
    /// The <c>aud</c> check enforces the RFC 9101 §10.2 reading: <c>aud</c> must
    /// equal the AS issuer URL resolved through
    /// <see cref="AuthorizationServerIntegration.ResolveIssuerAsync"/>. The
    /// EUDI/Microsoft <c>aud == client_id</c> reading is rejected; tenant-divergent
    /// audience policy is a planned future extension point and is not in scope here.
    /// </para>
    /// </remarks>
    private static async ValueTask<(AuthCodeRequestObject? RequestObject, ServerHttpResponse? EarlyExit)>
        VerifyAndValidateAuthCodeJarAsync(
            RequestFields fields,
            RequestContext context,
            AuthorizationServer server,
            CancellationToken cancellationToken)
    {
        if(!fields.TryGetValue(OAuthRequestParameters.Request, out string? compactJar)
            || string.IsNullOrWhiteSpace(compactJar))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "Missing request parameter."));
        }

        //RFC 9101 §5 explicitly permits the AS to require an outer client_id for
        //pre-verification client identification. Requiring it sidesteps the
        //"identify the registration before the JAR is verified" problem cleanly
        //and defends against substitution per RFC 9700 §4.6.
        if(!fields.TryGetValue(OAuthRequestParameters.ClientId, out string? outerClientId)
            || string.IsNullOrWhiteSpace(outerClientId))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest,
                "Missing outer client_id. The library requires an outer client_id alongside a JAR per RFC 9101 §5."));
        }

        ClientRecord? registration = context.Registration;
        if(registration is null)
        {
            return (null, ServerHttpResponse.Unauthorized(
                OAuthErrors.InvalidClient, "Unknown client."));
        }

        if(!string.Equals(outerClientId, registration.ClientId, StringComparison.Ordinal))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "Outer client_id does not match the registered client."));
        }

        //Resolve the JAR signing public key for this registration. The library
        //reads the JAR signing key id from the registration's JarSigning slot —
        //never from the JAR's own header. Doing the latter would defeat the
        //CVE-class header-key-injection defense.
        KeyId verificationKeyId;
        try
        {
            verificationKeyId = registration.GetDefaultSigningKeyId(KeyUsageContext.JarSigning);
        }
        catch(Exception ex) when(ex is KeyNotFoundException or InvalidOperationException)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                $"Registration '{registration.ClientId}' has no JAR signing key configured: {ex.Message}"));
        }

        ServerVerificationKeyResolverDelegate? resolver = server.Cryptography.VerificationKeyResolver;
        if(resolver is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, "VerificationKeyResolver is not configured."));
        }

        PublicKeyMemory? signingPublicKey = await resolver(
            verificationKeyId.Value, context, cancellationToken).ConfigureAwait(false);

        if(signingPublicKey is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                $"Verification key '{verificationKeyId.Value}' is unavailable."));
        }

        JwtHeaderDeserializer? headerDeserializer = server.Codecs.JwtHeaderDeserializer;
        JwtPayloadDeserializer? payloadDeserializer = server.Codecs.JwtPayloadDeserializer;
        DecodeDelegate? decoder = server.Codecs.Decoder;

        if(headerDeserializer is null || payloadDeserializer is null || decoder is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError, "Required JWT codecs are not configured."));
        }

        DateTimeOffset now = server.TimeProvider.GetUtcNow();

        //Clock skew and JAR lifetime ceiling come from per-request policy
        //(populated by ResolvePolicyAsync at dispatch entry). Defaults match
        //the historical TimingPolicy values for the strict reading.
        JarVerificationResult verification = await JarVerification.VerifyAsync(
            compactJar,
            signingPublicKey,
            now,
            context.ClockSkewTolerance,
            context.JarLifetimeCeiling,
            decoder,
            headerDeserializer,
            payloadDeserializer,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken).ConfigureAwait(false);

        if(verification is JarRejected rejected)
        {
            return (null, ServerHttpResponse.BadRequest(rejected.ErrorCode, rejected.Reason));
        }

        JarVerified verified = (JarVerified)verification;

        AuthCodeRequestObject requestObject;
        try
        {
            requestObject = verified.ProjectAuthCode();
        }
        catch(FormatException ex)
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject, ex.Message));
        }

        //RFC 9101 §10.2 — iss MUST equal client_id when present in the JAR. The
        //library treats iss as required for JAR per the same section; absence
        //is rejected.
        if(string.IsNullOrEmpty(requestObject.Iss)
            || !string.Equals(requestObject.Iss, requestObject.ClientId, StringComparison.Ordinal))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "JAR iss must be present and equal to client_id per RFC 9101 §10.2."));
        }

        //RFC 9700 §4.6 — the JAR's client_id MUST match the registered client.
        if(!string.Equals(requestObject.ClientId, registration.ClientId, StringComparison.Ordinal))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "JAR client_id does not match the registered client."));
        }

        //RFC 9101 §10.2, RFC 9700 §4.2 — aud MUST equal the AS issuer URL
        //(the FAPI-conformant reading). Tenant-divergent aud policy is a
        //planned follow-up. One call site here so the future delegate
        //extension point replaces a single method call. The validation runs
        //against verified.Claims rather than the projected requestObject.Aud
        //so the array form per RFC 7519 §4.1.3 is honoured — the projection
        //is single-string only.
        ServerHttpResponse? audFailure = await ValidateJarAudienceAsync(
            verified.Claims, registration, context, server, cancellationToken).ConfigureAwait(false);
        if(audFailure is not null)
        {
            return (null, audFailure);
        }

        //RFC 9700 §4.1 — redirect_uri exact-match against the registered set.
        if(!registration.AllowedRedirectUris.Contains(requestObject.RedirectUri))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                $"redirect_uri '{requestObject.RedirectUri}' is not among the registered redirect URIs."));
        }

        //Scope-required-on-request is a policy axis (Finding 4). Aligns the
        //JAR-bearing matcher with the PKCE PAR matcher — either both require
        //scope (the strict default) or both treat it as optional.
        if(context.ScopeRequiredOnRequest && string.IsNullOrEmpty(requestObject.Scope))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "scope is required under the active policy."));
        }

        //FAPI 2.0 §5.2.2, HAIP §3 — code_challenge_method MUST be S256 in the
        //strict default. Permissive deployments via policy.AllowedPkceMethods
        //may also accept "plain".
        if(!IsAcceptedPkceMethod(requestObject.CodeChallengeMethod, context))
        {
            return (null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "code_challenge_method is not accepted under the active policy."));
        }

        return (requestObject, null);
    }


    /// <summary>
    /// Validates the JAR <c>aud</c> claim against the AS issuer URL per RFC 9101
    /// §10.2 and RFC 9700 §4.2. Single call site so the future
    /// <c>ValidateJarAudienceDelegate</c> extension point — see the planned-
    /// follow-up note in the JAR brief — can replace one method call rather
    /// than tracking sprinkled checks. Delegates the string-or-array shape
    /// handling to <see cref="ValidationChecks.CheckTokenAudContainsExpectedIssuer"/>
    /// so both single-string and array-form <c>aud</c> per RFC 7519 §4.1.3 work.
    /// </summary>
    private static async ValueTask<ServerHttpResponse?> ValidateJarAudienceAsync(
        IReadOnlyDictionary<string, object> claims,
        ClientRecord registration,
        RequestContext context,
        AuthorizationServer server,
        CancellationToken cancellationToken)
    {
        if(!claims.ContainsKey(WellKnownJwtClaims.Aud))
        {
            return ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequestObject,
                "JAR aud claim is required per RFC 9101 §10.2.");
        }

        Uri issuerUri;
        try
        {
            issuerUri = server.Integration.ResolveIssuerAsync is not null
                ? await server.Integration.ResolveIssuerAsync(registration, context, cancellationToken)
                    .ConfigureAwait(false)
                : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken)
                    .ConfigureAwait(false);
        }
        catch(InvalidOperationException ex)
        {
            return ServerHttpResponse.ServerError(OAuthErrors.ServerError, ex.Message);
        }

        ValidationContext validationContext = new()
        {
            Context = context,
            TokenClaims = claims,
            ExpectedIssuer = issuerUri.ToString(),
            Now = server.TimeProvider.GetUtcNow(),
            ClockSkew = server.Timings.ClockSkewTolerance
        };

        List<Claim> result = await ValidationChecks.CheckTokenAudContainsExpectedIssuer(
            validationContext, cancellationToken).ConfigureAwait(false);

        if(result[0].Outcome == ClaimOutcome.Success)
        {
            return null;
        }

        return ServerHttpResponse.BadRequest(
            OAuthErrors.InvalidRequestObject,
            $"JAR aud does not match the AS issuer '{issuerUri}' per RFC 9101 §10.2.");
    }


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
            HttpMethod = WellKnownHttpMethods.Post,
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
                if(!WellKnownHttpMethods.IsPost(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRecord? registration = context.Registration;
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
                    CryptoTags.Sha256Digest,
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
                ClientRecord? registration = context.Registration;
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
                return ServerHttpResponse.Ok(sb.ToString(), WellKnownMediaTypes.Application.Json);
            }
        };


    private static ServerEndpoint BuildRevocation() =>
        new()
        {
            Name = "AuthCode.Revocation",
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = ServerCapabilityName.TokenRevocation,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,

            //Acceptance test: POST to /revoke for this registration with a
            //token body parameter per RFC 7009 §2.1.
            MatchesRequest = static (fields, context, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsPost(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRecord? registration = context.Registration;
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
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = ServerCapabilityName.TokenIntrospection,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,

            //Acceptance test: POST to /introspect for this registration with
            //a token body parameter per RFC 7662 §2.1.
            MatchesRequest = static (fields, context, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsPost(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                ClientRecord? registration = context.Registration;
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
    /// Composes the Authorize-completed redirect Location, optionally
    /// appending the RFC 9207 / FAPI 2.0 §5.3.1.2 <c>iss</c> response
    /// parameter under <c>policy.EmitIssOnRedirect</c>. Closes audit Finding
    /// 1 (missing <c>iss</c> on Authorize redirect).
    /// </summary>
    /// <remarks>
    /// The issuer URL source order mirrors <c>DefaultIssuerResolver</c>:
    /// <see cref="ClientRecord.IssuerUri"/> first, then the per-request
    /// <see cref="RequestContextExtensions.Issuer"/>. When neither is
    /// populated the parameter is omitted rather than failing the redirect —
    /// the strict-default deployment populates one of the two and the
    /// permissive deployment opts out via <c>policy.EmitIssOnRedirect</c>.
    /// </remarks>
    private static ServerHttpResponse BuildAuthorizeRedirect(
        ServerCodeIssuedState code, RequestContext context)
    {
        string location = $"{code.RedirectUri}?code={Uri.EscapeDataString(code.CodeHash)}";

        if(context.EmitIssOnRedirect)
        {
            Uri? issuer = context.Registration?.IssuerUri ?? context.Issuer;
            if(issuer is not null)
            {
                location += $"&iss={Uri.EscapeDataString(issuer.ToString())}";
            }
        }

        return ServerHttpResponse.Redirect(location);
    }


    /// <summary>
    /// Returns whether <paramref name="method"/> is an accepted PKCE
    /// <c>code_challenge_method</c> value under the deployment's policy. The
    /// strict default (<see cref="PkceMethodSet.S256Only"/>) accepts only
    /// <c>S256</c>; the permissive baseline
    /// (<see cref="PkceMethodSet.S256AndPlain"/>) also accepts <c>plain</c>.
    /// </summary>
    private static bool IsAcceptedPkceMethod(string? method, RequestContext context)
    {
        if(string.IsNullOrEmpty(method))
        {
            return false;
        }

        if(string.Equals(method, OAuthRequestParameters.CodeChallengeMethodS256,
            StringComparison.Ordinal))
        {
            return true;
        }

        return context.AllowedPkceMethods == PkceMethodSet.S256AndPlain
            && string.Equals(method, "plain", StringComparison.Ordinal);
    }


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
        //AuthCode endpoint handlers run inside sync endpoint-builder lambdas that
        //don't have an await boundary at this layer; bridge to async via
        //CryptographicKeyEvents.ComputeDigestSyncBridge. The computeDigest
        //parameter is retained for API stability but the registered delegate is
        //used directly via the bridge — both resolve to the same backend in
        //practice. If a future profile needs a non-default qualifier here, the
        //helper migrates to async at that point.
        _ = computeDigest;

        int inputByteCount = System.Text.Encoding.ASCII.GetByteCount(input);
        using IMemoryOwner<byte> inputOwner = pool.Rent(inputByteCount);
        Span<byte> inputBytes = inputOwner.Memory.Span[..inputByteCount];
        System.Text.Encoding.ASCII.GetBytes(input, inputBytes);

        using DigestValue digest = CryptographicKeyEvents.ComputeDigestSyncBridge(
            inputOwner.Memory[..inputByteCount], digestByteLength, algorithmTag, pool);

        return encoder(digest.AsReadOnlySpan());
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
