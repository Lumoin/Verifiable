using System.Diagnostics;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Endpoint builder for the OpenID Federation 1.0 self-published
/// <c>/.well-known/openid-federation</c> Entity Configuration JWT
/// per <see href="https://openid.net/specs/openid-federation-1_0.html#section-9">Federation §9</see>.
/// </summary>
/// <remarks>
/// <para>
/// Register at startup via
/// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>:
/// </para>
/// <code>
/// new EndpointBuilderSet([
///     MetadataEndpoints.Builder,
///     FederationEndpoints.Builder,
///     ...
/// ]);
/// </code>
/// <para>
/// Per-tenant — a registration carrying
/// <see cref="WellKnownFederationCapabilityIdentifiers.PublishEntityConfiguration"/>
/// and a non-null <see cref="ClientRecord.FederationEntityId"/> contributes
/// one EC endpoint at a URL the application chooses via
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>.
/// The library never assumes a path shape; tenant separation can be
/// path-segment, subdomain, header-based, or anything the application's
/// URL resolver returns.
/// </para>
/// <para>
/// <strong>Signing.</strong> The EC is signed via
/// <see cref="Jws.SignAsync{TJwtPart}(TJwtPart, TJwtPart, JwtPartEncoder{TJwtPart}, EncodeDelegate, PrivateKeyMemory, System.Buffers.MemoryPool{byte}, System.Threading.CancellationToken)"/>'s
/// registry-based overload, so the wire <c>alg</c> derives entirely from
/// the private key's tag through the registered
/// <see cref="SigningDelegate"/>. No signing algorithm is hardcoded
/// here — EC, RSA, OKP, ML-DSA all flow through the same path.
/// </para>
/// <para>
/// <strong>Serialization firewall.</strong> The EC and SS header / payload
/// JSON are emitted by hand via
/// <see cref="EntityStatementJsonBuilder"/>'s
/// <see cref="System.Text.StringBuilder"/> walker; no
/// <c>System.Text.Json</c> or other JSON-library dependency is taken on
/// here. See the remarks on
/// <see cref="EntityStatementJsonBuilder"/> for the rationale.
/// </para>
/// </remarks>
[DebuggerDisplay("FederationEndpoints")]
public static class FederationEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        bool hasFederationSigning =
            ((ClientRecord)registration).FederationEntityId is not null
            && ((ClientRecord)registration).SigningKeys.ContainsKey(KeyUsageContext.FederationEntitySignature);

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownFederationCapabilityIdentifiers.PublishEntityConfiguration)
            && hasFederationSigning)
        {
            candidates.Add(BuildEntityConfiguration());
        }

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownFederationCapabilityIdentifiers.PublishSubordinateStatement)
            && hasFederationSigning)
        {
            candidates.Add(BuildFederationFetch());
        }

        //The list endpoint's §8.2 response is an unsigned JSON array, so it
        //needs only a federation Entity Identifier — no federation signing
        //key. An entity may therefore advertise its subordinate membership
        //without also issuing Subordinate Statements (though most that list
        //also fetch).
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownFederationCapabilityIdentifiers.ListSubordinates)
            && ((ClientRecord)registration).FederationEntityId is not null)
        {
            candidates.Add(BuildFederationList());
        }

        //The resolve endpoint returns a SIGNED Resolve Response JWT, so it
        //needs the federation signing key (unlike the unsigned list).
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownFederationCapabilityIdentifiers.ResolveTrustChain)
            && hasFederationSigning)
        {
            candidates.Add(BuildFederationResolve());
        }

        //The explicit registration endpoint returns a SIGNED Explicit
        //Registration Response JWT, so it needs the federation signing key.
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownFederationCapabilityIdentifiers.RegisterClientsExplicitly)
            && hasFederationSigning)
        {
            candidates.Add(BuildFederationRegistration());
        }

        //The historical keys endpoint returns a SIGNED JWK Set JWT, so it
        //needs the federation signing key (like resolve and explicit
        //registration).
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownFederationCapabilityIdentifiers.PublishHistoricalKeys)
            && hasFederationSigning)
        {
            candidates.Add(BuildFederationHistoricalKeys());
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    /// <summary>
    /// Builds the <c>/.well-known/openid-federation</c> Entity
    /// Configuration endpoint.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Stateless: <see cref="ServerEndpoint.BuildInputAsync"/> assembles
    /// the EC payload, signs it via the registry-based
    /// <see cref="Jws.SignAsync{TJwtPart}(TJwtPart, TJwtPart, JwtPartEncoder{TJwtPart}, EncodeDelegate, PrivateKeyMemory, System.Buffers.MemoryPool{byte}, System.Threading.CancellationToken)"/>,
    /// and short-circuits the dispatcher with an early
    /// <see cref="ServerHttpResponse.Ok(string, string)"/>. The
    /// <see cref="ServerEndpoint.BuildResponse"/> hook is never reached.
    /// </para>
    /// </remarks>
    private static EndpointCandidate BuildEntityConfiguration() =>
        new()
        {
            Name = WellKnownEndpointNames.FederationEntityConfiguration,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownFederationCapabilityIdentifiers.PublishEntityConfiguration,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            //DiscoveryMetadataKey null — the federation EC is itself a
            //well-known document; it is not advertised inside the OAuth
            //discovery document.

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
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                if(((ClientRecord)registration).FederationEntityId is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Federation Entity Configuration endpoint requires "
                        + "ClientRecord.FederationEntityId to be set."));
                }

                if(!((ClientRecord)registration).SigningKeys.TryGetValue(
                        KeyUsageContext.FederationEntitySignature, out SigningKeySet? federationKeys)
                    || federationKeys.Current.IsEmpty)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Federation Entity Configuration endpoint requires "
                        + "a SigningKeySet under KeyUsageContext.FederationEntitySignature "
                        + "with a non-empty Current list."));
                }

                if(oauth.Cryptography.SigningKeyResolver is null
                    || oauth.Cryptography.VerificationKeyResolver is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Federation Entity Configuration endpoint requires "
                        + "AuthorizationServerCryptography.SigningKeyResolver and "
                        + "VerificationKeyResolver to be configured."));
                }

                EncodeDelegate? base64UrlEncoder = oauth.Codecs.Encoder;
                if(base64UrlEncoder is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Federation Entity Configuration endpoint requires "
                        + "AuthorizationServerCodecs.Encoder to be configured."));
                }

                //Pick the first Current signing key — the same default the
                //library uses elsewhere via ClientRecord.GetDefaultSigningKeyId.
                KeyId signingKeyId = federationKeys.Current[0];

                PrivateKeyMemory? privateKey = await oauth.Cryptography.SigningKeyResolver(
                    signingKeyId, registration.TenantId, context, ct).ConfigureAwait(false);
                if(privateKey is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Federation signing key '{signingKeyId.Value}' could not be resolved."));
                }

                //Build the jwks claim from the FederationEntitySignature
                //PublishedKeys — pre-published Incoming, Current, and
                //Retiring slots. This is intentionally a different scope
                //from the OAuth /jwks endpoint (which aggregates across
                //usage contexts) so the federation surface and the
                //token-signing surface stay independent.
                IReadOnlyDictionary<string, object> jwks = await BuildFederationJwksAsync(
                    server, registration, federationKeys, base64UrlEncoder, context, ct).ConfigureAwait(false);

                //Application-supplied contribution (metadata blocks, authority
                //hints, additional claims). Queries and return values flow
                //through the AS pipeline so the integration delegate sees the
                //full ExchangeContext and may mutate freely per call.
                FederationEntityConfigurationContribution contribution =
                    oauth.ContributeFederationMetadataAsync is null
                        ? FederationEntityConfigurationContribution.Empty
                        : await oauth.ContributeFederationMetadataAsync(
                            registration, context, ct).ConfigureAwait(false);

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                DateTimeOffset expiresAt = now + oauth.Timings.FederationEntityConfigurationLifetime;

                string alg = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

                //Advertise the registration types this OP accepts (Federation §12)
                //from the registration's enabled federation capabilities, so the
                //published Entity Configuration matches what the endpoints actually
                //serve. Automatic (§12.1) first, then explicit (§12.2).
                List<string> clientRegistrationTypesSupported = [];
                if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownFederationCapabilityIdentifiers.RegisterClientsAutomatically))
                {
                    clientRegistrationTypesSupported.Add(WellKnownFederationRegistrationTypeValues.Automatic);
                }

                if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownFederationCapabilityIdentifiers.RegisterClientsExplicitly))
                {
                    clientRegistrationTypesSupported.Add(WellKnownFederationRegistrationTypeValues.Explicit);
                }

                Dictionary<string, object> headerDict =
                    EntityStatementJsonBuilder.BuildHeader(signingKeyId.Value, alg);
                Dictionary<string, object> payloadDict =
                    EntityStatementJsonBuilder.BuildConfigurationPayload(
                        ((ClientRecord)registration).FederationEntityId,
                        now,
                        expiresAt,
                        jwks,
                        contribution,
                        clientRegistrationTypesSupported);

                JwsMessage jwsMessage = await Jws.SignAsync(
                    headerDict,
                    payloadDict,
                    EntityStatementJsonBuilder.EncodeJwtPart,
                    base64UrlEncoder,
                    privateKey,
                    System.Buffers.MemoryPool<byte>.Shared,
                    ct).ConfigureAwait(false);

                string compactJws = JwsSerialization.SerializeCompact(jwsMessage, base64UrlEncoder);

                return (null, ServerHttpResponse.Ok(
                    compactJws, WellKnownMediaTypes.Application.EntityStatementJwt));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the <c>federation_fetch_endpoint</c> per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.1">Federation §8.1</see>.
    /// Stateless: <c>GET ?sub=&lt;subject&gt;</c> arrives, the application
    /// supplies the per-subject statement body via
    /// <see cref="AuthorizationServerIntegration.ResolveSubordinateStatementAsync"/>,
    /// the library signs the result with the entity's federation signing
    /// key (the same key used for the entity's own EC), and the dispatcher
    /// short-circuits with the signed JWS response.
    /// </summary>
    /// <remarks>
    /// When the application returns <see langword="null"/> from the
    /// resolver the endpoint responds HTTP 404 — the queried subject is
    /// not a known subordinate. The URL the matcher binds to is whatever
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// returned for
    /// <see cref="WellKnownEndpointNames.FederationFetch"/>; the
    /// application advertises this URL in its EC metadata
    /// (<c>federation_entity.federation_fetch_endpoint</c>).
    /// </remarks>
    private static EndpointCandidate BuildFederationFetch() =>
        new()
        {
            Name = WellKnownEndpointNames.FederationFetch,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownFederationCapabilityIdentifiers.PublishSubordinateStatement,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

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
                if(!fields.ContainsKey(FederationEndpointParameterNames.Sub))
                {
                    //Federation §8.1: sub is required. Without it the
                    //endpoint cannot identify what subordinate the client
                    //is asking about.
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
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                if(((ClientRecord)registration).FederationEntityId is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_fetch_endpoint requires "
                        + "ClientRecord.FederationEntityId to be set."));
                }

                if(oauth.ResolveSubordinateStatementAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_fetch_endpoint requires "
                        + "AuthorizationServerIntegration.ResolveSubordinateStatementAsync "
                        + "to be configured."));
                }

                if(!((ClientRecord)registration).SigningKeys.TryGetValue(
                        KeyUsageContext.FederationEntitySignature, out SigningKeySet? federationKeys)
                    || federationKeys.Current.IsEmpty)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_fetch_endpoint requires "
                        + "a SigningKeySet under KeyUsageContext.FederationEntitySignature "
                        + "with a non-empty Current list."));
                }

                if(oauth.Cryptography.SigningKeyResolver is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_fetch_endpoint requires "
                        + "AuthorizationServerCryptography.SigningKeyResolver to be configured."));
                }

                EncodeDelegate? base64UrlEncoder = oauth.Codecs.Encoder;
                if(base64UrlEncoder is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_fetch_endpoint requires "
                        + "AuthorizationServerCodecs.Encoder to be configured."));
                }

                if(!fields.TryGetValue(FederationEndpointParameterNames.Sub, out string? subjectValue)
                    || string.IsNullOrWhiteSpace(subjectValue))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Missing sub query parameter."));
                }

                EntityIdentifier subject;
                try
                {
                    subject = new EntityIdentifier(subjectValue);
                }
                catch(ArgumentException ex)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        $"sub parameter is not a valid Entity Identifier: {ex.Message}"));
                }

                //Specification conformance case. A Subordinate Statement is
                //iss != sub by definition (Federation §3): an entity cannot
                //issue a Subordinate Statement about itself — that would be its
                //self-issued Entity Configuration. Reject a fetch whose sub is
                //this entity's own identifier rather than emitting a malformed
                //statement. Uri equality normalises the empty-vs-"/" path so the
                //guard is not defeated by a trailing slash.
                if(Uri.TryCreate(subject.Value, UriKind.Absolute, out Uri? subjectUri)
                    && subjectUri == ((ClientRecord)registration).FederationEntityId)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "sub must not equal the issuing entity — a Subordinate Statement "
                        + "is not self-issued (Federation §3)."));
                }

                SubordinateStatementContribution? contribution =
                    await oauth.ResolveSubordinateStatementAsync(
                        subject, registration, context, ct).ConfigureAwait(false);

                if(contribution is null)
                {
                    //Federation §8.1 does not pin the not-found body shape;
                    //the library's standard 404 with an empty body is the
                    //conservative wire choice and matches the rest of the
                    //AS's not-found path.
                    return (null, ServerHttpResponse.NotFound());
                }

                KeyId signingKeyId = federationKeys.Current[0];
                PrivateKeyMemory? privateKey = await oauth.Cryptography.SigningKeyResolver(
                    signingKeyId, registration.TenantId, context, ct).ConfigureAwait(false);
                if(privateKey is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Federation signing key '{signingKeyId.Value}' could not be resolved."));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                DateTimeOffset expiresAt = now + oauth.Timings.FederationEntityConfigurationLifetime;

                string alg = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

                Dictionary<string, object> headerDict =
                    EntityStatementJsonBuilder.BuildHeader(signingKeyId.Value, alg);
                Dictionary<string, object> payloadDict =
                    EntityStatementJsonBuilder.BuildSubordinatePayload(
                        issuerEntityIdentifier: ((ClientRecord)registration).FederationEntityId,
                        subjectEntityIdentifier: new Uri(subject.Value),
                        issuedAt: now,
                        expiresAt: expiresAt,
                        contribution: contribution);

                JwsMessage jwsMessage = await Jws.SignAsync(
                    headerDict,
                    payloadDict,
                    EntityStatementJsonBuilder.EncodeJwtPart,
                    base64UrlEncoder,
                    privateKey,
                    System.Buffers.MemoryPool<byte>.Shared,
                    ct).ConfigureAwait(false);

                string compactJws = JwsSerialization.SerializeCompact(jwsMessage, base64UrlEncoder);

                return (null, ServerHttpResponse.Ok(
                    compactJws, WellKnownMediaTypes.Application.EntityStatementJwt));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the <c>federation_list_endpoint</c> per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.2">Federation §8.2</see>.
    /// Stateless: a bare <c>GET</c> (optionally carrying an
    /// <c>entity_type</c> filter) arrives, the application supplies the
    /// subordinate membership via
    /// <see cref="AuthorizationServerIntegration.ResolveSubordinateListAsync"/>,
    /// and the dispatcher short-circuits with the §8.2 unsigned JSON array
    /// of Entity Identifier strings.
    /// </summary>
    /// <remarks>
    /// Unlike the <c>federation_fetch_endpoint</c>, the §8.2 response is
    /// <em>unsigned</em> — it states only the membership, not any assertion
    /// about a subject — so the endpoint takes no federation signing key.
    /// The URL the matcher binds to is whatever
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// returned for <see cref="WellKnownEndpointNames.FederationList"/>; the
    /// application advertises this URL in its EC metadata
    /// (<c>federation_entity.federation_list_endpoint</c>).
    /// </remarks>
    private static EndpointCandidate BuildFederationList() =>
        new()
        {
            Name = WellKnownEndpointNames.FederationList,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownFederationCapabilityIdentifiers.ListSubordinates,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

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

                //Federation §8.2 takes no required parameter — the list
                //returns the entity's full subordinate membership, and
                //entity_type / trust_marked / intermediate are optional
                //filters. Matching is therefore method + path only.
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                if(((ClientRecord)registration).FederationEntityId is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_list_endpoint requires "
                        + "ClientRecord.FederationEntityId to be set."));
                }

                if(oauth.ResolveSubordinateListAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_list_endpoint requires "
                        + "AuthorizationServerIntegration.ResolveSubordinateListAsync "
                        + "to be configured."));
                }

                //Optional §8.2 entity_type filter. A blank value is treated
                //as absent rather than as a filter that matches nothing.
                EntityTypeIdentifier? entityTypeFilter = null;
                if(fields.TryGetValue(FederationEndpointParameterNames.EntityType, out string? entityTypeValue)
                    && !string.IsNullOrWhiteSpace(entityTypeValue))
                {
                    entityTypeFilter = new EntityTypeIdentifier(entityTypeValue);
                }

                IReadOnlyList<EntityIdentifier> subordinates =
                    await oauth.ResolveSubordinateListAsync(
                        entityTypeFilter, registration, context, ct).ConfigureAwait(false)
                    ?? [];

                string json = BuildSubordinateListJson(subordinates);

                return (null, ServerHttpResponse.Ok(
                    json, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Serialises a subordinate membership list as the OpenID Federation
    /// 1.0 §8.2 response body: a bare JSON array of Entity Identifier
    /// strings (<c>["https://a.example","https://b.example"]</c>). Built by
    /// hand through <see cref="JsonAppender"/> to honour the
    /// <c>Verifiable.OAuth</c> serialization firewall — no
    /// <c>System.Text.Json</c> dependency is taken on.
    /// </summary>
    private static string BuildSubordinateListJson(IReadOnlyList<EntityIdentifier> subordinates)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('[');
            for(int i = 0; i < subordinates.Count; ++i)
            {
                if(i > 0)
                {
                    sb.Append(',');
                }

                sb.Append('"');
                JsonAppender.AppendEscapedString(sb, subordinates[i].Value);
                sb.Append('"');
            }

            sb.Append(']');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Builds the <c>federation_resolve_endpoint</c> per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3">Federation §8.3</see>.
    /// Stateless: <c>GET ?sub=&lt;subject&gt;[&amp;anchor=&lt;anchor&gt;][&amp;type=&lt;entity-type&gt;]</c>
    /// arrives, the application resolves the subject via
    /// <see cref="AuthorizationServerIntegration.ResolveSubjectTrustChainAsync"/>,
    /// the library assembles and signs the §8.3 Resolve Response JWT
    /// (<c>typ = resolve-response+jwt</c>) with the resolver's federation
    /// signing key, and the dispatcher short-circuits with it.
    /// </summary>
    /// <remarks>
    /// When the application returns <see langword="null"/> the endpoint
    /// responds HTTP 404 — the subject could not be resolved to the
    /// requested anchor. The URL the matcher binds to is whatever
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// returned for <see cref="WellKnownEndpointNames.FederationResolve"/>;
    /// the application advertises this URL in its EC metadata
    /// (<c>federation_entity.federation_resolve_endpoint</c>).
    /// </remarks>
    private static EndpointCandidate BuildFederationResolve() =>
        new()
        {
            Name = WellKnownEndpointNames.FederationResolve,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownFederationCapabilityIdentifiers.ResolveTrustChain,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

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

                //sub is §8.3-required, but a missing sub is a malformed
                //request (400), not a non-match — matching on method + path
                //and validating sub in BuildInputAsync gives the conformant
                //400 rather than a misleading 404.
                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                if(((ClientRecord)registration).FederationEntityId is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_resolve_endpoint requires "
                        + "ClientRecord.FederationEntityId to be set."));
                }

                if(oauth.ResolveSubjectTrustChainAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_resolve_endpoint requires "
                        + "AuthorizationServerIntegration.ResolveSubjectTrustChainAsync "
                        + "to be configured."));
                }

                if(!((ClientRecord)registration).SigningKeys.TryGetValue(
                        KeyUsageContext.FederationEntitySignature, out SigningKeySet? federationKeys)
                    || federationKeys.Current.IsEmpty)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_resolve_endpoint requires "
                        + "a SigningKeySet under KeyUsageContext.FederationEntitySignature "
                        + "with a non-empty Current list."));
                }

                if(oauth.Cryptography.SigningKeyResolver is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_resolve_endpoint requires "
                        + "AuthorizationServerCryptography.SigningKeyResolver to be configured."));
                }

                EncodeDelegate? base64UrlEncoder = oauth.Codecs.Encoder;
                if(base64UrlEncoder is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_resolve_endpoint requires "
                        + "AuthorizationServerCodecs.Encoder to be configured."));
                }

                if(!fields.TryGetValue(FederationEndpointParameterNames.Sub, out string? subjectValue)
                    || string.IsNullOrWhiteSpace(subjectValue))
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Missing sub query parameter."));
                }

                EntityIdentifier subject;
                try
                {
                    subject = new EntityIdentifier(subjectValue);
                }
                catch(ArgumentException ex)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        $"sub parameter is not a valid Entity Identifier: {ex.Message}"));
                }

                //anchor is §8.3-optional — pass it through when present.
                EntityIdentifier? trustAnchor = null;
                if(fields.TryGetValue(FederationEndpointParameterNames.Anchor, out string? anchorValue)
                    && !string.IsNullOrWhiteSpace(anchorValue))
                {
                    try
                    {
                        trustAnchor = new EntityIdentifier(anchorValue);
                    }
                    catch(ArgumentException ex)
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            $"anchor parameter is not a valid Entity Identifier: {ex.Message}"));
                    }
                }

                //Optional §8.3 type filter (the resolve endpoint's
                //entity-type filter; spelled 'type', distinct from the §8.2
                //list endpoint's 'entity_type').
                EntityTypeIdentifier? entityTypeFilter = null;
                if(fields.TryGetValue(FederationEndpointParameterNames.Type, out string? typeValue)
                    && !string.IsNullOrWhiteSpace(typeValue))
                {
                    entityTypeFilter = new EntityTypeIdentifier(typeValue);
                }

                ResolveResponseContribution? contribution =
                    await oauth.ResolveSubjectTrustChainAsync(
                        subject, trustAnchor, entityTypeFilter, registration, context, ct).ConfigureAwait(false);

                if(contribution is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                KeyId signingKeyId = federationKeys.Current[0];
                PrivateKeyMemory? privateKey = await oauth.Cryptography.SigningKeyResolver(
                    signingKeyId, registration.TenantId, context, ct).ConfigureAwait(false);
                if(privateKey is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Federation signing key '{signingKeyId.Value}' could not be resolved."));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                DateTimeOffset expiresAt = now + oauth.Timings.FederationEntityConfigurationLifetime;

                string alg = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

                Dictionary<string, object> headerDict =
                    EntityStatementJsonBuilder.BuildHeader(
                        signingKeyId.Value, alg, WellKnownFederationMediaTypes.ResolveResponseJwt);
                Dictionary<string, object> payloadDict =
                    EntityStatementJsonBuilder.BuildResolveResponsePayload(
                        resolverEntityIdentifier: ((ClientRecord)registration).FederationEntityId,
                        subjectEntityIdentifier: subject.Value,
                        issuedAt: now,
                        expiresAt: expiresAt,
                        contribution: contribution);

                JwsMessage jwsMessage = await Jws.SignAsync(
                    headerDict,
                    payloadDict,
                    EntityStatementJsonBuilder.EncodeJwtPart,
                    base64UrlEncoder,
                    privateKey,
                    System.Buffers.MemoryPool<byte>.Shared,
                    ct).ConfigureAwait(false);

                string compactJws = JwsSerialization.SerializeCompact(jwsMessage, base64UrlEncoder);

                return (null, ServerHttpResponse.Ok(
                    compactJws, WellKnownMediaTypes.Application.ResolveResponseJwt));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the <c>federation_historical_keys_endpoint</c> per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.7">Federation §8.7</see>.
    /// Stateless: <c>GET</c> arrives, the application supplies the entity's
    /// historical (rotated and revoked) keys via
    /// <see cref="AuthorizationServerIntegration.ResolveHistoricalKeysAsync"/>,
    /// the library assembles and signs the §8.7.3 Historical Keys JWT
    /// (<c>typ = jwk-set+jwt</c>) with the entity's federation signing key,
    /// and the dispatcher short-circuits with it.
    /// </summary>
    /// <remarks>
    /// When the application returns <see langword="null"/> the endpoint
    /// responds HTTP 404 — the entity has no historical keys to publish,
    /// mirroring the <c>federation_resolve_endpoint</c> null-contribution
    /// contract. The URL the matcher binds to is whatever
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// returned for <see cref="WellKnownEndpointNames.FederationHistoricalKeys"/>;
    /// the application advertises this URL in its EC metadata
    /// (<c>federation_entity.federation_historical_keys_endpoint</c>).
    /// </remarks>
    private static EndpointCandidate BuildFederationHistoricalKeys() =>
        new()
        {
            Name = WellKnownEndpointNames.FederationHistoricalKeys,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownFederationCapabilityIdentifiers.PublishHistoricalKeys,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

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
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                if(((ClientRecord)registration).FederationEntityId is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_historical_keys_endpoint requires "
                        + "ClientRecord.FederationEntityId to be set."));
                }

                if(oauth.ResolveHistoricalKeysAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_historical_keys_endpoint requires "
                        + "AuthorizationServerIntegration.ResolveHistoricalKeysAsync "
                        + "to be configured."));
                }

                if(!((ClientRecord)registration).SigningKeys.TryGetValue(
                        KeyUsageContext.FederationEntitySignature, out SigningKeySet? federationKeys)
                    || federationKeys.Current.IsEmpty)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_historical_keys_endpoint requires "
                        + "a SigningKeySet under KeyUsageContext.FederationEntitySignature "
                        + "with a non-empty Current list."));
                }

                if(oauth.Cryptography.SigningKeyResolver is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_historical_keys_endpoint requires "
                        + "AuthorizationServerCryptography.SigningKeyResolver to be configured."));
                }

                EncodeDelegate? base64UrlEncoder = oauth.Codecs.Encoder;
                if(base64UrlEncoder is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_historical_keys_endpoint requires "
                        + "AuthorizationServerCodecs.Encoder to be configured."));
                }

                HistoricalKeysContribution? contribution =
                    await oauth.ResolveHistoricalKeysAsync(
                        registration, context, ct).ConfigureAwait(false);

                if(contribution is null)
                {
                    return (null, ServerHttpResponse.NotFound());
                }

                KeyId signingKeyId = federationKeys.Current[0];
                PrivateKeyMemory? privateKey = await oauth.Cryptography.SigningKeyResolver(
                    signingKeyId, registration.TenantId, context, ct).ConfigureAwait(false);
                if(privateKey is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Federation signing key '{signingKeyId.Value}' could not be resolved."));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();

                string alg = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

                Dictionary<string, object> headerDict =
                    EntityStatementJsonBuilder.BuildHeader(
                        signingKeyId.Value, alg, WellKnownFederationMediaTypes.HistoricalKeysJwt);
                Dictionary<string, object> payloadDict =
                    EntityStatementJsonBuilder.BuildHistoricalKeysPayload(
                        entityIdentifier: ((ClientRecord)registration).FederationEntityId,
                        issuedAt: now,
                        contribution: contribution);

                JwsMessage jwsMessage = await Jws.SignAsync(
                    headerDict,
                    payloadDict,
                    EntityStatementJsonBuilder.EncodeJwtPart,
                    base64UrlEncoder,
                    privateKey,
                    System.Buffers.MemoryPool<byte>.Shared,
                    ct).ConfigureAwait(false);

                string compactJws = JwsSerialization.SerializeCompact(jwsMessage, base64UrlEncoder);

                return (null, ServerHttpResponse.Ok(
                    compactJws, WellKnownMediaTypes.Application.HistoricalKeysJwt));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the <c>federation_registration_endpoint</c> per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-12.2">Federation §12.2</see>.
    /// Stateless: the RP <c>POST</c>s its signed Entity Configuration in the
    /// request body, the application processes it via
    /// <see cref="AuthorizationServerIntegration.ResolveExplicitRegistrationAsync"/>,
    /// the library assembles and signs the §12.2 Explicit Registration
    /// Response JWT (<c>typ = explicit-registration-response+jwt</c>) with the
    /// OP's federation signing key, and the dispatcher short-circuits with it.
    /// </summary>
    /// <remarks>
    /// The library does not parse the posted Entity Configuration — it passes
    /// the raw compact JWS to the application delegate (preserving the
    /// <c>Verifiable.OAuth</c> serialization firewall) and only builds and
    /// signs the structural response. When the application returns
    /// <see langword="null"/> the endpoint responds HTTP 400 — the RP could
    /// not be registered.
    /// </remarks>
    private static EndpointCandidate BuildFederationRegistration() =>
        new()
        {
            Name = WellKnownEndpointNames.FederationRegistration,
            HttpMethod = WellKnownHttpMethods.Post,
            Capability = WellKnownFederationCapabilityIdentifiers.RegisterClientsExplicitly,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,

            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsPost(req.Method))
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
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                if(((ClientRecord)registration).FederationEntityId is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_registration_endpoint requires "
                        + "ClientRecord.FederationEntityId to be set."));
                }

                if(oauth.ResolveExplicitRegistrationAsync is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_registration_endpoint requires "
                        + "AuthorizationServerIntegration.ResolveExplicitRegistrationAsync "
                        + "to be configured."));
                }

                if(!((ClientRecord)registration).SigningKeys.TryGetValue(
                        KeyUsageContext.FederationEntitySignature, out SigningKeySet? federationKeys)
                    || federationKeys.Current.IsEmpty)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_registration_endpoint requires "
                        + "a SigningKeySet under KeyUsageContext.FederationEntitySignature "
                        + "with a non-empty Current list."));
                }

                if(oauth.Cryptography.SigningKeyResolver is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_registration_endpoint requires "
                        + "AuthorizationServerCryptography.SigningKeyResolver to be configured."));
                }

                EncodeDelegate? base64UrlEncoder = oauth.Codecs.Encoder;
                if(base64UrlEncoder is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "federation_registration_endpoint requires "
                        + "AuthorizationServerCodecs.Encoder to be configured."));
                }

                IncomingRequest? req = context.IncomingRequest;
                if(req is null || req.Body.IsEmpty || req.Body.Bytes.IsEmpty)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Explicit registration request body is missing. POST the RP's "
                        + "signed Entity Configuration as the request body."));
                }

                //The body is the RP's compact JWS Entity Configuration —
                //ASCII/UTF-8 text. Decode to a string and hand it to the
                //application, which parses, verifies, and chain-validates it
                //(the library stays out of JWS parsing here).
                string registrationRequest = Encoding.UTF8.GetString(req.Body.Bytes.Span);

                ExplicitRegistrationContribution? contribution =
                    await oauth.ResolveExplicitRegistrationAsync(
                        registrationRequest, registration, context, ct).ConfigureAwait(false);

                if(contribution is null)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "The Relying Party could not be registered."));
                }

                KeyId signingKeyId = federationKeys.Current[0];
                PrivateKeyMemory? privateKey = await oauth.Cryptography.SigningKeyResolver(
                    signingKeyId, registration.TenantId, context, ct).ConfigureAwait(false);
                if(privateKey is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        $"Federation signing key '{signingKeyId.Value}' could not be resolved."));
                }

                DateTimeOffset now = server.TimeProvider.GetUtcNow();
                DateTimeOffset expiresAt = now + oauth.Timings.FederationEntityConfigurationLifetime;

                string alg = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

                Dictionary<string, object> headerDict =
                    EntityStatementJsonBuilder.BuildHeader(
                        signingKeyId.Value, alg, WellKnownFederationMediaTypes.ExplicitRegistrationResponseJwt);
                Dictionary<string, object> payloadDict =
                    EntityStatementJsonBuilder.BuildExplicitRegistrationResponsePayload(
                        opEntityIdentifier: ((ClientRecord)registration).FederationEntityId,
                        rpEntityIdentifier: contribution.Subject,
                        issuedAt: now,
                        expiresAt: expiresAt,
                        contribution: contribution);

                JwsMessage jwsMessage = await Jws.SignAsync(
                    headerDict,
                    payloadDict,
                    EntityStatementJsonBuilder.EncodeJwtPart,
                    base64UrlEncoder,
                    privateKey,
                    System.Buffers.MemoryPool<byte>.Shared,
                    ct).ConfigureAwait(false);

                string compactJws = JwsSerialization.SerializeCompact(jwsMessage, base64UrlEncoder);

                return (null, ServerHttpResponse.Ok(
                    compactJws, WellKnownMediaTypes.Application.ExplicitRegistrationResponseJwt));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Builds the EC's <c>jwks</c> claim from the registration's
    /// <see cref="KeyUsageContext.FederationEntitySignature"/>
    /// <see cref="SigningKeySet.PublishedKeys"/>. Each
    /// <see cref="KeyId"/> resolves through the
    /// <see cref="AuthorizationServerCryptography.VerificationKeyResolver"/>;
    /// the JWK conversion goes through
    /// <see cref="CryptoFormatConversions.DefaultAlgorithmToJwkConverter"/>
    /// so the key's tag drives the JWK <c>kty</c> / <c>crv</c> / <c>n</c> /
    /// <c>e</c> / etc. choice without algorithm hardcoding.
    /// </summary>
    private static async ValueTask<IReadOnlyDictionary<string, object>> BuildFederationJwksAsync(
        EndpointServer server,
        ClientRecord registration,
        SigningKeySet federationKeys,
        EncodeDelegate base64UrlEncoder,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        List<object> keys = [];

        foreach(KeyId keyId in federationKeys.PublishedKeys)
        {
            PublicKeyMemory? publicKey = await oauth.Cryptography.VerificationKeyResolver!(
                keyId, registration.TenantId, context, cancellationToken).ConfigureAwait(false);
            if(publicKey is null)
            {
                continue;
            }

            JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
                publicKey.Tag.Get<CryptoAlgorithm>(),
                publicKey.Tag.Get<Purpose>(),
                publicKey.AsReadOnlySpan(),
                base64UrlEncoder);

            jwk.Kid = keyId.Value;
            jwk.Use = WellKnownJwkValues.UseSig;

            keys.Add(jwk);
        }

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["keys"] = keys
        };
    }
}
