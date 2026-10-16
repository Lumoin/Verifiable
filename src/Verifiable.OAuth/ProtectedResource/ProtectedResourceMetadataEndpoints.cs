using System.Text;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// Serves the OAuth 2.0 Protected Resource Metadata document (RFC 9728 §3) for
/// a protected resource co-located with the server: a capability-gated
/// <c>GET</c> returning the §2 parameter set as <c>application/json</c> with
/// <c>200 OK</c> (§3.2).
/// </summary>
/// <remarks>
/// <para>
/// The library derives what it can and cannot get wrong: <c>resource</c> is
/// the resolved issuer identity — the same identifier the §3 well-known URL is
/// formed from, keeping the §3.3 validation invariant true by construction —
/// and <c>jwks_uri</c> is read off the per-request endpoint chain. Where the
/// server validates DPoP proofs, <c>dpop_signing_alg_values_supported</c> is the
/// one list it holds every proof to; where its resources require DPoP-bound
/// access tokens
/// (<see cref="AuthorizationServerIntegration.IsDpopBoundAccessTokenRequiredAtResources"/>),
/// the document states <c>dpop_bound_access_tokens_required: true</c> and
/// <c>bearer_methods_supported: []</c>, and a contribution stating otherwise is
/// answered <c>server_error</c> with no document. Everything
/// else is application data supplied through the
/// <see cref="AuthorizationServerIntegration.ContributeProtectedResourceMetadataAsync"/>
/// seam, and <c>signed_metadata</c> (§2.2) is produced by dropping the
/// assembled claim set to the application's
/// <see cref="AuthorizationServerIntegration.SignProtectedResourceMetadataAsync"/>
/// signer, which owns the key, the algorithm, and the spec-required <c>iss</c>
/// claim. The same values go into both the plain document and the signed JWT,
/// so they cannot diverge.
/// </para>
/// <para>
/// Activation requires the
/// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>
/// capability. The §5 <c>WWW-Authenticate</c> <c>resource_metadata</c>
/// challenge parameter is each resource server's own 401 surface:
/// <see cref="ProtectedResourceChallenge"/> builds and parses it, and the
/// co-located SSF transmitter endpoints attach it to their 401s when this
/// capability is active.
/// </para>
/// </remarks>
public static class ProtectedResourceMetadataEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static EndpointBuilderDelegate Builder { get; } = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata))
        {
            candidates.Add(BuildProtectedResourceMetadata());
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    /// <summary>
    /// Builds the <c>GET /.well-known/oauth-protected-resource</c> metadata
    /// endpoint per RFC 9728 §3.1/§3.2. Stateless: resolve → assemble →
    /// serialise, short-circuiting the dispatcher with the document.
    /// </summary>
    private static EndpointCandidate BuildProtectedResourceMetadata() =>
        new()
        {
            Name = WellKnownEndpointNames.ProtectedResourceMetadata,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata,
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
                EndpointServer server = context.RequestServer!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "Client registration not found in context."));
                }

                EndpointChain? chain = context.EndpointChain;
                if(chain is null)
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError,
                        "EndpointChain not on context for protected resource metadata "
                        + "emission. DispatchAsync sets this; this code path is only "
                        + "reachable through dispatch."));
                }

                //§2 resource (REQUIRED) + §3.3: the resource identifier is the
                //same identity the well-known URL is formed from, so the
                //consumer's resource-match validation holds by construction.
                //Resolved through the same seam the discovery document uses.
                Uri resource;
                try
                {
                    resource = oauth.ResolveIssuerAsync is not null
                        ? (await oauth.ResolveIssuerAsync(registration, context, ct)
                            .ConfigureAwait(false))!
                        : await DefaultIssuerResolver.ResolveAsync(registration, context, ct)
                            .ConfigureAwait(false);
                }
                catch(InvalidOperationException)
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "Resource identifier (issuer) not found in context."));
                }

                //Application-supplied §2 values the library cannot derive.
                ProtectedResourceMetadataContribution contributed =
                    oauth.ContributeProtectedResourceMetadataAsync is null
                        ? ProtectedResourceMetadataContribution.Empty
                        : await oauth.ContributeProtectedResourceMetadataAsync(
                            registration, context, ct).ConfigureAwait(false);

                //RFC 9728 Section 2: dpop_bound_access_tokens_required states "whether the protected resource
                //always requires the use of DPoP-bound access tokens"; when the server's resources do, a contribution
                //stating otherwise contradicts them, a fault of the host's own configuration, and no document is served.
                bool isDpopBoundAccessTokenRequired = oauth.IsDpopBoundAccessTokenRequiredAtResources;
                if(isDpopBoundAccessTokenRequired
                    && (contributed.DpopBoundAccessTokensRequired is false || contributed.BearerMethodsSupported is { Count: > 0 }))
                {
                    return (null, ServerHttpResponse.ServerError(
                        OAuthErrors.ServerError, WellKnownOAuthErrorDescriptions.ServerNotReady));
                }

                //RFC 9728 Section 2: dpop_signing_alg_values_supported lists the algorithms "supported by the resource
                //server for validating Demonstrating Proof of Possession (DPoP) proof JWTs". Where the server validates
                //proofs, that is the one list it holds every proof to; the contribution's member is read only where it
                //validates none.
                IReadOnlyList<string>? dpopSigningAlgorithms = Dpop.DpopRequestReading.IsProofValidationWired(oauth)
                    ? await AuthCode.Server.DpopTokenEndpointValidation.ResolveAcceptedProofAlgorithmsAsync(
                        oauth, registration, context, ct).ConfigureAwait(false)
                    : contributed.DpopSigningAlgValuesSupported;

                ProtectedResourceMetadataContribution contribution = contributed with
                {
                    DpopSigningAlgValuesSupported = dpopSigningAlgorithms,
                    DpopBoundAccessTokensRequired = isDpopBoundAccessTokenRequired switch
                    {
                        true => true,
                        false => contributed.DpopBoundAccessTokensRequired
                    },
                    BearerMethodsSupported = isDpopBoundAccessTokenRequired switch
                    {
                        true => [],
                        false => contributed.BearerMethodsSupported
                    }
                };

                //§2 jwks_uri — read off the chain the dispatcher built, so the
                //advertised URL is the one the matcher binds to.
                string? jwksUri = null;
                foreach(ServerEndpoint chainEndpoint in chain)
                {
                    if(string.Equals(chainEndpoint.Name, WellKnownEndpointNames.MetadataJwks, StringComparison.Ordinal))
                    {
                        jwksUri = chainEndpoint.ResolvedUri.ToString();
                        break;
                    }
                }

                //§2.2 signed_metadata — the library assembles the claim set and
                //drops out to the application's signer (which owns the key, the
                //algorithm, and the spec-required iss claim).
                string? signedMetadata = null;
                if(oauth.SignProtectedResourceMetadataAsync is not null)
                {
                    JwtPayload claims = BuildMetadataClaims(resource, jwksUri, contribution);
                    signedMetadata = await oauth.SignProtectedResourceMetadataAsync(
                        claims, registration, context, ct).ConfigureAwait(false);
                }

                string metadataJson = BuildMetadataJson(resource, jwksUri, contribution, signedMetadata);

                return (null, ServerHttpResponse.Ok(
                    metadataJson, WellKnownMediaTypes.Application.Json));
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Serialises the RFC 9728 §2 metadata document. Parameters with zero
    /// values are omitted per Section 3.2, but for a stated empty
    /// <c>bearer_methods_supported</c>, written as <c>[]</c> (RFC 9728 Section 2:
    /// "The empty array [] can be used to indicate that no bearer methods are
    /// supported."). Built by hand through
    /// <see cref="JsonAppender"/> to honour the <c>Verifiable.OAuth</c>
    /// serialization firewall.
    /// </summary>
    private static string BuildMetadataJson(
        Uri resource,
        string? jwksUri,
        ProtectedResourceMetadataContribution contribution,
        string? signedMetadata)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            _ = sb.Append('{');

            bool first = true;
            JsonAppender.AppendUriField(
                sb, ProtectedResourceMetadataParameterNames.Resource, resource, ref first);

            AppendArrayField(sb, ProtectedResourceMetadataParameterNames.AuthorizationServers,
                contribution.AuthorizationServers, ref first);

            if(!string.IsNullOrEmpty(jwksUri))
            {
                JsonAppender.AppendStringField(
                    sb, ProtectedResourceMetadataParameterNames.JwksUri, jwksUri, ref first);
            }

            AppendArrayField(sb, ProtectedResourceMetadataParameterNames.ScopesSupported,
                contribution.ScopesSupported, ref first);
            AppendStatedListField(sb, ProtectedResourceMetadataParameterNames.BearerMethodsSupported,
                contribution.BearerMethodsSupported, ref first);
            AppendArrayField(sb, ProtectedResourceMetadataParameterNames.ResourceSigningAlgValuesSupported,
                contribution.ResourceSigningAlgValuesSupported, ref first);

            AppendOptionalString(sb, ProtectedResourceMetadataParameterNames.ResourceName,
                contribution.ResourceName, ref first);
            AppendOptionalString(sb, ProtectedResourceMetadataParameterNames.ResourceDocumentation,
                contribution.ResourceDocumentation, ref first);
            AppendOptionalString(sb, ProtectedResourceMetadataParameterNames.ResourcePolicyUri,
                contribution.ResourcePolicyUri, ref first);
            AppendOptionalString(sb, ProtectedResourceMetadataParameterNames.ResourceTosUri,
                contribution.ResourceTosUri, ref first);

            if(contribution.TlsClientCertificateBoundAccessTokens is bool mtlsBound)
            {
                JsonAppender.AppendBoolField(
                    sb, ProtectedResourceMetadataParameterNames.TlsClientCertificateBoundAccessTokens,
                    mtlsBound, ref first);
            }

            AppendArrayField(sb, ProtectedResourceMetadataParameterNames.AuthorizationDetailsTypesSupported,
                contribution.AuthorizationDetailsTypesSupported, ref first);
            AppendArrayField(sb, ProtectedResourceMetadataParameterNames.DpopSigningAlgValuesSupported,
                contribution.DpopSigningAlgValuesSupported, ref first);

            if(contribution.DpopBoundAccessTokensRequired is bool dpopRequired)
            {
                JsonAppender.AppendBoolField(
                    sb, ProtectedResourceMetadataParameterNames.DpopBoundAccessTokensRequired,
                    dpopRequired, ref first);
            }

            //§2.1 language-tagged variants, emitted verbatim.
            if(contribution.LocalizedParameters is { Count: > 0 } localized)
            {
                foreach(KeyValuePair<string, string> entry in localized)
                {
                    JsonAppender.AppendStringField(sb, entry.Key, entry.Value, ref first);
                }
            }

            if(!string.IsNullOrEmpty(signedMetadata))
            {
                JsonAppender.AppendStringField(
                    sb, ProtectedResourceMetadataParameterNames.SignedMetadata, signedMetadata, ref first);
            }

            _ = sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Assembles the §2.2 metadata claim set handed to the application's
    /// signer — the same values the plain document carries, so the signed JWT
    /// cannot diverge from the advertised document. The signer adds the
    /// spec-required <c>iss</c> claim. A <c>signed_metadata</c> claim is never
    /// part of the set (§2.2: it SHOULD NOT appear as a claim in the JWT).
    /// </summary>
    private static JwtPayload BuildMetadataClaims(
        Uri resource, string? jwksUri, ProtectedResourceMetadataContribution contribution)
    {
        //OriginalString matches the plain document's AppendUriField emission,
        //so the signed claim and the advertised value are byte-identical.
        JwtPayload claims = new()
        {
            [ProtectedResourceMetadataParameterNames.Resource] = resource.OriginalString
        };

        if(contribution.AuthorizationServers is { Count: > 0 } servers)
        {
            claims[ProtectedResourceMetadataParameterNames.AuthorizationServers] = servers;
        }

        if(!string.IsNullOrEmpty(jwksUri))
        {
            claims[ProtectedResourceMetadataParameterNames.JwksUri] = jwksUri;
        }

        if(contribution.ScopesSupported is { Count: > 0 } scopes)
        {
            claims[ProtectedResourceMetadataParameterNames.ScopesSupported] = scopes;
        }

        //RFC 9728 Section 2: "The empty array [] can be used to indicate that no bearer methods are supported.", the
        //named exception to Section 3.2's omission of zero values, so a stated empty list is carried as stated.
        if(contribution.BearerMethodsSupported is { } bearerMethods)
        {
            claims[ProtectedResourceMetadataParameterNames.BearerMethodsSupported] = bearerMethods;
        }

        if(contribution.ResourceSigningAlgValuesSupported is { Count: > 0 } signingAlgs)
        {
            claims[ProtectedResourceMetadataParameterNames.ResourceSigningAlgValuesSupported] = signingAlgs;
        }

        if(!string.IsNullOrEmpty(contribution.ResourceName))
        {
            claims[ProtectedResourceMetadataParameterNames.ResourceName] = contribution.ResourceName;
        }

        if(!string.IsNullOrEmpty(contribution.ResourceDocumentation))
        {
            claims[ProtectedResourceMetadataParameterNames.ResourceDocumentation] = contribution.ResourceDocumentation;
        }

        if(!string.IsNullOrEmpty(contribution.ResourcePolicyUri))
        {
            claims[ProtectedResourceMetadataParameterNames.ResourcePolicyUri] = contribution.ResourcePolicyUri;
        }

        if(!string.IsNullOrEmpty(contribution.ResourceTosUri))
        {
            claims[ProtectedResourceMetadataParameterNames.ResourceTosUri] = contribution.ResourceTosUri;
        }

        if(contribution.TlsClientCertificateBoundAccessTokens is bool mtlsBound)
        {
            claims[ProtectedResourceMetadataParameterNames.TlsClientCertificateBoundAccessTokens] = mtlsBound;
        }

        if(contribution.AuthorizationDetailsTypesSupported is { Count: > 0 } detailTypes)
        {
            claims[ProtectedResourceMetadataParameterNames.AuthorizationDetailsTypesSupported] = detailTypes;
        }

        if(contribution.DpopSigningAlgValuesSupported is { Count: > 0 } dpopAlgs)
        {
            claims[ProtectedResourceMetadataParameterNames.DpopSigningAlgValuesSupported] = dpopAlgs;
        }

        if(contribution.DpopBoundAccessTokensRequired is bool dpopRequired)
        {
            claims[ProtectedResourceMetadataParameterNames.DpopBoundAccessTokensRequired] = dpopRequired;
        }

        if(contribution.LocalizedParameters is { Count: > 0 } localized)
        {
            foreach(KeyValuePair<string, string> entry in localized)
            {
                claims[entry.Key] = entry.Value;
            }
        }

        return claims;
    }


    /// <summary>
    /// Appends the string member <paramref name="name"/> when <paramref name="value"/> holds text, and nothing for a
    /// <see langword="null"/> or empty value: <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728
    /// Section 3.2</see>, "Parameters with zero values MUST be omitted from the response."
    /// </summary>
    /// <param name="sb">The document being written.</param>
    /// <param name="name">The member name.</param>
    /// <param name="value">The member value, or <see langword="null"/>.</param>
    /// <param name="first">Whether no member has been written yet; cleared when this one is.</param>
    private static void AppendOptionalString(StringBuilder sb, string name, string? value, ref bool first)
    {
        if(!string.IsNullOrEmpty(value))
        {
            JsonAppender.AppendStringField(sb, name, value, ref first);
        }
    }


    /// <summary>
    /// Appends the JSON array member <paramref name="name"/> when <paramref name="values"/> holds at least one value, and
    /// nothing for a <see langword="null"/> or empty list: <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC
    /// 9728 Section 3.2</see>, "Parameters with multiple values are represented as JSON arrays. Parameters with zero values
    /// MUST be omitted from the response."
    /// </summary>
    /// <param name="sb">The document being written.</param>
    /// <param name="name">The member name.</param>
    /// <param name="values">The member values, or <see langword="null"/>.</param>
    /// <param name="first">Whether no member has been written yet; cleared when this one is.</param>
    private static void AppendArrayField(
        StringBuilder sb, string name, IReadOnlyList<string>? values, ref bool first)
    {
        if(values is { Count: > 0 })
        {
            JsonAppender.AppendStringArrayField(sb, name, values, ref first);
        }
    }


    /// <summary>
    /// Appends the JSON array member <paramref name="name"/> whenever <paramref name="values"/> is stated, an empty list
    /// as <c>[]</c>, and nothing for <see langword="null"/>: the member whose empty array has a meaning of its own,
    /// <c>bearer_methods_supported</c> (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section
    /// 2</see>: "The empty array [] can be used to indicate that no bearer methods are supported."), the named exception
    /// to Section 3.2's omission of zero values.
    /// </summary>
    /// <param name="sb">The document being written.</param>
    /// <param name="name">The member name.</param>
    /// <param name="values">The member values, or <see langword="null"/> when the member is not stated.</param>
    /// <param name="first">Whether no member has been written yet; cleared when this one is.</param>
    private static void AppendStatedListField(
        StringBuilder sb, string name, IReadOnlyList<string>? values, ref bool first)
    {
        if(values is not null)
        {
            JsonAppender.AppendStringArrayField(sb, name, values, ref first);
        }
    }
}
