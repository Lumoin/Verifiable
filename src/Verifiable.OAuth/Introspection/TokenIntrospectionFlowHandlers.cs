using Verifiable.Core;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.IdJag;

namespace Verifiable.OAuth.Introspection;

/// <summary>
/// The client-side RFC 7662 introspection exchange <see cref="TokenIntrospectionClient.IntrospectAsync"/> runs: one
/// form POST to the authorization server's <c>introspection_endpoint</c>, authenticated by the protected resource's
/// registration, read by <see cref="OAuthResponseParsers.ParseTokenIntrospectionResponse"/>.
/// </summary>
/// <remarks>
/// <para>
/// The steps run in this order: the caller's arguments are checked; the authorization server's metadata is resolved
/// through <see cref="OAuthClientInfrastructure.ResolveAuthorizationServerMetadataAsync"/> and held to the registration's
/// pinned issuer (<see cref="AuthorizationServerMetadataValidation.IsIssuerMatch"/>); the metadata names the
/// <c>introspection_endpoint</c>; the outbound fetch policy admits that endpoint before any dial; the form carries
/// <c>token</c> and, when the request names one, <c>token_type_hint</c>; the registration's client authentication is
/// attached by the token endpoint's own attachment (<c>none</c>, <c>client_secret_post</c>, <c>client_secret_basic</c>,
/// <c>private_key_jwt</c>, whose assertion names the audience the registration's
/// <see cref="ClientRegistration.ClientAssertionAudience"/> selects: the issuer identifier by default, the introspection
/// endpoint's URL under <see cref="ClientAssertionAudience.TokenEndpoint"/>); the request is sent once through
/// <see cref="OAuthClientInfrastructure.SendFormPostAsync"/> with the authentication's header fields alone, never through
/// the DPoP-retrying sender, so it carries no <c>DPoP</c> field whatever DPoP the infrastructure wires; a 3xx answer is
/// refused and never followed; the answer is read with the infrastructure's pool.
/// </para>
/// <para>
/// The exchange caches nothing, retries nothing and falls back to nothing: a transport exception passes to the caller,
/// and every introspection is one exchange, the application's own cache stopping at the answer's
/// <see cref="TokenIntrospectionResult.ExpiresAt"/>.
/// </para>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.1">RFC 7662 Section 2.1</see>: "The protected resource
/// calls the introspection endpoint using an HTTP POST [RFC7231] request with parameters sent as
/// "application/x-www-form-urlencoded" data as defined in [W3C.REC-html5-20141028]." and "To prevent token scanning
/// attacks, the endpoint MUST also require some form of authorization to access this endpoint, such as client
/// authentication as described in OAuth 2.0 [RFC6749] or a separate OAuth 2.0 access token such as the bearer token
/// described in OAuth 2.0 Bearer Token Usage [RFC6750]."
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "Note that the resource
/// server does not send a DPoP proof with the introspection request, and the authorization server does not validate an
/// access token's DPoP binding at the introspection endpoint. Rather, the resource server uses the data of the
/// introspection response to validate the access token binding itself locally."
/// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-4">RFC 7662 Section 4</see>: "If the response contains the
/// "exp" parameter (expiration), the response MUST NOT be cached beyond the time indicated therein."
/// </para>
/// </remarks>
internal static class TokenIntrospectionFlowHandlers
{
    /// <summary>
    /// Checks the caller's arguments and runs the exchange (<see cref="IntrospectCoreAsync"/>).
    /// </summary>
    /// <param name="request">The token and the hint.</param>
    /// <param name="infrastructure">The infrastructure the request is sent through.</param>
    /// <param name="registration">The resource's registration at the authorization server.</param>
    /// <param name="context">The per-operation exchange context.</param>
    /// <param name="clientAssertionOptions">The <c>private_key_jwt</c> signing inputs, or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The introspection result or the failure.</returns>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><see cref="TokenIntrospectionRequest.Token"/> is empty.</exception>
    /// <exception cref="InvalidOperationException">
    /// The registration's method needs <see cref="ClientRegistration.AuthenticationKeyMaterial"/> it does not carry, or is
    /// <c>private_key_jwt</c> with no <paramref name="clientAssertionOptions"/>.
    /// </exception>
    internal static ValueTask<Result<TokenIntrospectionResult, OAuthParseError>> IntrospectAsync(
        TokenIntrospectionRequest request,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(request.Token, nameof(request));

        return IntrospectCoreAsync(request, infrastructure, registration, context, clientAssertionOptions, cancellationToken);
    }


    /// <summary>
    /// Runs the exchange in the order the class remarks state, each refusal answered before anything is sent.
    /// </summary>
    /// <param name="request">The token and the hint.</param>
    /// <param name="infrastructure">The infrastructure the request is sent through.</param>
    /// <param name="registration">The resource's registration at the authorization server.</param>
    /// <param name="context">The per-operation exchange context.</param>
    /// <param name="clientAssertionOptions">The <c>private_key_jwt</c> signing inputs, or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The introspection result or the failure.</returns>
    private static async ValueTask<Result<TokenIntrospectionResult, OAuthParseError>> IntrospectCoreAsync(
        TokenIntrospectionRequest request,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        CancellationToken cancellationToken)
    {
        AuthorizationServerMetadataResolution resolution = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);
        if(resolution is not AuthorizationServerMetadataResolved resolved)
        {
            return Result.Failure<TokenIntrospectionResult, OAuthParseError>(
                IdJagFlowHandlers.BuildAuthorizationServerMetadataResolutionFailure(resolution));
        }

        AuthorizationServerMetadata metadata = resolved.Metadata;

        //RFC 8414 Section 3.3: metadata whose issuer is not the one the registration pins is not used.
        if(!AuthorizationServerMetadataValidation.IsIssuerMatch(metadata, registration.AuthorizationServerIssuer))
        {
            return Result.Failure<TokenIntrospectionResult, OAuthParseError>(
                new OAuthInvalidFieldValue(
                    AuthorizationServerMetadataParameterNames.Issuer,
                    string.Empty,
                    "The authorization server metadata issuer does not match this registration's pinned AuthorizationServerIssuer.",
                    new DecisionSupport("The resolved authorization server metadata names another issuer, so none of it is used.")
                    {
                        SpecificationReference = "RFC 8414 Section 3.3"
                    }));
        }

        if(metadata.IntrospectionEndpoint is not Uri introspectionEndpoint)
        {
            return Result.Failure<TokenIntrospectionResult, OAuthParseError>(
                new OAuthInvalidFieldValue(
                    AuthorizationServerMetadataParameterNames.IntrospectionEndpoint,
                    string.Empty,
                    "The authorization server metadata names no introspection_endpoint.",
                    new DecisionSupport("The authorization server publishes no introspection endpoint, so no request is sent.")
                    {
                        SpecificationReference = "RFC 8414 Section 2"
                    }));
        }

        //RFC 7662 Section 2: "The introspection endpoint MUST be protected by a transport-layer security mechanism as
        //described in Section 4.", so the outbound fetch policy refuses a non-https endpoint before any request is sent.
        if(IdJagFlowHandlers.EvaluateOutboundPolicy(introspectionEndpoint, context, infrastructure, "RFC 7662 Section 2") is OAuthOutboundFetchPolicyDenied policyDenial)
        {
            return Result.Failure<TokenIntrospectionResult, OAuthParseError>(policyDenial);
        }

        OutgoingFormFields form = new(capacity: 6)
        {
            [OAuthRequestParameterNames.Token] = request.Token
        };

        if(request.TokenTypeHint is string tokenTypeHint)
        {
            form[OAuthRequestParameterNames.TokenTypeHint] = tokenTypeHint;
        }

        OutgoingHeaders authenticationHeaders = await TokenEndpointClientOperations.AttachClientAuthenticationAsync(
            form,
            registration,
            introspectionEndpoint,
            clientAssertionOptions,
            infrastructure,
            infrastructure.TimeProvider.GetUtcNow(),
            context,
            cancellationToken).ConfigureAwait(false);

        //RFC 9449 Section 6.2: the resource server does not send a DPoP proof with the introspection request, so the
        //request goes through the one plain send with the authentication's header fields alone.
        HttpResponseData response = await infrastructure.SendFormPostAsync(
            introspectionEndpoint, form, authenticationHeaders, context, cancellationToken).ConfigureAwait(false);

        //The request carries the token and the resource's credential; a redirect followed would send both to the origin
        //its Location field names (RFC 9110 Section 15.4.8).
        if(CredentialBearingRedirect.Refuse(introspectionEndpoint, response) is OAuthRedirectRefused redirectRefusal)
        {
            return Result.Failure<TokenIntrospectionResult, OAuthParseError>(redirectRefusal);
        }

        return OAuthResponseParsers.ParseTokenIntrospectionResponse(response, infrastructure.MemoryPool);
    }
}
