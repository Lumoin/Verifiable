using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode.Server;
using Verifiable.OAuth.AuthCode.Server.States;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Endpoint builder module for the OAuth 2.0 Authorization Code flow with PKCE.
/// </summary>
/// <remarks>
/// <para>
/// Produces PAR, Authorize (PAR-backed), Direct Authorize, and Token endpoints.
/// Register at startup via <see cref="AuthorizationServerOptions.EndpointBuilders"/>:
/// </para>
/// <code>
/// options.EndpointBuilders =
/// [
///     AuthCodeEndpoints.Builder,
///     MetadataEndpoints.Builder
/// ];
/// </code>
/// </remarks>
[DebuggerDisplay("AuthCodeEndpoints")]
public static class AuthCodeEndpoints
{
    private const string Get = "GET";
    private const string Post = "POST";


    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="AuthorizationServerOptions.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, options) =>
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


    private static ServerEndpoint BuildPar() =>
        new()
        {
            HttpMethod = Post,
            PathTemplate = ServerEndpointPaths.Par,
            Capability = ServerCapabilityName.PushedAuthorization,
            StartsNewFlow = true,
            Kind = FlowKind.AuthCodeServer,
            BuildInputAsync = static async (fields, context, currentState, options, ct) =>
            {
                if(!fields.TryGetValue(OAuthRequestParameters.ClientId, out string? clientId)
                    || string.IsNullOrWhiteSpace(clientId))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing client_id."));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.CodeChallenge, out string? challenge)
                    || string.IsNullOrWhiteSpace(challenge))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing code_challenge."));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.CodeChallengeMethod, out string? method)
                    || !string.Equals(method, OAuthRequestParameters.CodeChallengeMethodS256,
                        StringComparison.Ordinal))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "code_challenge_method must be S256."));
                }

                if(!fields.TryGetValue(OAuthRequestParameters.RedirectUri, out string? redirectUriString)
                    || !Uri.TryCreate(redirectUriString, UriKind.Absolute, out Uri? redirectUri))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest, "Missing or invalid redirect_uri."));
                }

                fields.TryGetValue(OAuthRequestParameters.Scope, out string? scope);
                scope ??= string.Empty;

                fields.TryGetValue(JCose.WellKnownJwtClaims.Nonce, out string? nonce);
                nonce ??= string.Empty;

                DateTimeOffset now = options.TimeProvider.GetUtcNow();

                string flowId = context.FlowId!;
                string requestUriToken = Guid.NewGuid().ToString("N");
                Uri requestUri = new($"urn:ietf:params:oauth:request_uri:{requestUriToken}");
                DateTimeOffset expiresAt = now.AddSeconds(60);

                return (new ServerParValidated(
                    FlowId: flowId,
                    RequestUri: requestUri,
                    CodeChallenge: challenge,
                    RedirectUri: redirectUri,
                    Scope: scope,
                    ClientId: clientId,
                    Nonce: nonce,
                    ExpectedIssuer: clientId,
                    ReceivedAt: now,
                    ExpiresAt: expiresAt), null);
            },
            BuildResponse = static (state, _, _) =>
            {
                if(state is not ParRequestReceivedState par)
                {
                    return ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Unexpected state after PAR.");
                }

                string body =
                    $"{{\"request_uri\":\"{par.RequestUri}\",\"expires_in\":60}}";
                return ServerHttpResponse.Ok(body, "application/json");
            }
        };


    private static ServerEndpoint BuildAuthorize() =>
        new()
        {
            HttpMethod = Get,
            PathTemplate = ServerEndpointPaths.Authorize,
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

            MatchesRequest = static fields =>
                fields.ContainsKey(OAuthRequestParameters.RequestUri),
            BuildInputAsync = static (fields, context, currentState, options, ct) =>
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

                DateTimeOffset authTime = context.AuthTime ?? options.TimeProvider.GetUtcNow();

                DateTimeOffset now = options.TimeProvider.GetUtcNow();
                string rawCode = Guid.NewGuid().ToString("N");
                string codeHash = ComputeDigestBase64Url(
                    rawCode, HashAlgorithmName.SHA256,
                    options.HashFunctionSelector!, options.Encoder!);

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
            HttpMethod = Get,
            PathTemplate = ServerEndpointPaths.Authorize,
            Capability = ServerCapabilityName.DirectAuthorization,
            StartsNewFlow = true,
            Kind = FlowKind.AuthCodeServer,

            MatchesRequest = static fields =>
                !fields.ContainsKey(OAuthRequestParameters.RequestUri),

            BuildInputAsync = static (fields, context, currentState, options, ct) =>
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

                fields.TryGetValue(JCose.WellKnownJwtClaims.Nonce, out string? nonce);
                nonce ??= string.Empty;

                DateTimeOffset now = options.TimeProvider.GetUtcNow();
                string flowId = context.FlowId!;
                DateTimeOffset expiresAt = now.AddSeconds(600);

                string rawCode = Guid.NewGuid().ToString("N");
                string codeHash = ComputeDigestBase64Url(
                    rawCode, HashAlgorithmName.SHA256,
                    options.HashFunctionSelector!, options.Encoder!);

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
    /// Default producer list when <see cref="AuthorizationServerOptions.TokenProducers"/>
    /// is not configured. Single producer matches the library's historical
    /// access-token-only response shape.
    /// </summary>
    private static readonly IReadOnlyList<TokenProducer> DefaultTokenProducers =
        [TokenProducer.Rfc9068AccessToken];


    private static ServerEndpoint BuildToken() =>
        new()
        {
            HttpMethod = Post,
            PathTemplate = ServerEndpointPaths.Token,
            Capability = ServerCapabilityName.AuthorizationCode,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,
            ExtractCorrelationKey = static (path, fields, context) =>
                fields.TryGetValue(OAuthRequestParameters.Code, out string? code)
                    && !string.IsNullOrWhiteSpace(code) ? code : null,
            BuildInputAsync = static async (fields, context, currentState, options, ct) =>
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
                    verifier, HashAlgorithmName.SHA256,
                    options.HashFunctionSelector!, options.Encoder!);
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

                ClientRegistration? registration =
                    await options.LoadClientRegistrationAsync!(clientId, context, ct)
                        .ConfigureAwait(false);

                if(registration is null)
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Unknown client."));
                }

                Uri issuerUri;
                try
                {
                    issuerUri = options.ResolveIssuerAsync is not null
                        ? await options.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false)
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException ex)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, ex.Message));
                }

                DateTimeOffset now = options.TimeProvider.GetUtcNow();

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
                    options.TokenProducers ?? DefaultTokenProducers;

                IReadOnlyList<ClaimContributor> contributors =
                    options.ClaimContributors ?? [];

                Dictionary<string, string> issuedTokens = new(producers.Count);
                Dictionary<string, IssuedTokenAudit> issuedAudits = new(producers.Count);
                DateTimeOffset latestExpiry = now;

                foreach(TokenProducer producer in producers)
                {
                    if(!await options.CheckCapabilityAsync(
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
                        options, registration, producer.KeyUsage, context, ct)
                        .ConfigureAwait(false);

                    PrivateKeyMemory? signingKey = await options.SigningKeyResolver!(
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
                        issuance, options, signingKeyId, algorithm, ct).ConfigureAwait(false);

                    JwtPayload payload = output.Payload;

                    foreach(ClaimContributor contributor in contributors)
                    {
                        if(!await contributor.IsApplicable(issuance, producer, ct)
                            .ConfigureAwait(false))
                        {
                            continue;
                        }

                        IReadOnlyDictionary<string, object> contributed =
                            await contributor.BuildAsync(issuance, producer, ct)
                                .ConfigureAwait(false);

                        foreach(KeyValuePair<string, object> entry in contributed)
                        {
                            payload[entry.Key] = entry.Value;
                        }
                    }

                    UnsignedJwt unsigned = new(output.Header, payload);

                    using JwsMessage jws = await unsigned.SignAsync(
                        signingKey,
                        options.JwtHeaderSerializer!,
                        options.JwtPayloadSerializer!,
                        options.Encoder!,
                        SensitiveMemoryPool<byte>.Shared,
                        ct).ConfigureAwait(false);

                    string compactJws = JwsSerialization.SerializeCompact(jws, options.Encoder!);

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
                int expiresIn = accessAudit is null
                    ? 3600
                    : (int)(accessAudit.ExpiresAt - accessAudit.IssuedAt).TotalSeconds;

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
            HttpMethod = Post,
            PathTemplate = ServerEndpointPaths.Revoke,
            Capability = ServerCapabilityName.TokenRevocation,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,
            BuildInputAsync = static (fields, context, currentState, options, ct) =>
                ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>(
                    (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Revocation not yet implemented."))),
            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    private static ServerEndpoint BuildIntrospection() =>
        new()
        {
            HttpMethod = Post,
            PathTemplate = ServerEndpointPaths.Introspect,
            Capability = ServerCapabilityName.TokenIntrospection,
            StartsNewFlow = false,
            Kind = FlowKind.AuthCodeServer,
            BuildInputAsync = static (fields, context, currentState, options, ct) =>
                ValueTask.FromResult<(OAuthFlowInput?, ServerHttpResponse?)>(
                    (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, "Introspection not yet implemented."))),
            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    internal static string ComputeDigestBase64Url(
        string input,
        HashAlgorithmName algorithm,
        HashFunctionSelector hashSelector,
        EncodeDelegate encoder)
    {
        HashFunction hash = hashSelector(algorithm);
        byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
        byte[] digest = hash(inputBytes);

        return encoder(digest);
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
