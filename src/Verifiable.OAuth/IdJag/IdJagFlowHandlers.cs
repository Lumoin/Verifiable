using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// Drives the two client-side ID-JAG token-endpoint exchanges of
/// draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.3 (mint) and §4.4 (redeem) over the injected
/// transport. Both authenticate the confidential client (§9.1) with the client assertion (RFC 7523 §2.2) the
/// registration's method names, composed under the key or the secret the registration carries, and parse the response
/// through the infrastructure's token-response parser. A credential the registration cannot form is refused, typed,
/// before anything is resolved or sent.
/// </summary>
public static class IdJagFlowHandlers
{
    /// <summary>
    /// Mints an ID-JAG: a Token Exchange (<c>requested_token_type</c> id-jag, §4.3) to the IdP's token
    /// endpoint, authenticated with the client assertion the registration's method names. The returned token response
    /// carries the ID-JAG in its <see cref="TokenResponse.AccessToken"/> (<c>token_type</c> N_A, §4.3.4); a credential
    /// the registration cannot form is the <see cref="OAuthClientAssertionRefused"/> failure, before any send.
    /// </summary>
    public static async ValueTask<Result<TokenResponse, OAuthParseError>> MintAsync(
        IdJagMintOptions options,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        var credential = ResolveCredential(registration, options.ClientAssertion);

        if(!credential.IsSuccess)
        {
            return Result<TokenResponse, OAuthParseError>.Failure(credential.Error);
        }

        AuthorizationServerMetadataResolution resolution = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

        if(resolution is not AuthorizationServerMetadataResolved resolved)
        {
            return Result<TokenResponse, OAuthParseError>.Failure(
                BuildAuthorizationServerMetadataResolutionFailure(resolution));
        }

        AuthorizationServerMetadata metadata = resolved.Metadata;
        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        Uri tokenEndpoint = metadata.TokenEndpoint!;

        OutgoingFormFields form = new(capacity: 9)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = options.Audience,
            [OAuthRequestParameterNames.SubjectToken] = options.SubjectToken,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(options.SubjectTokenType)
        };

        //§4.3 / RFC 8707 section 2: each requested resource becomes its OWN repeated resource occurrence
        //on the wire (OutgoingFormFields.Add) — the genuine RFC 8707 multi-resource wire form the
        //authorization server's own ReadResource/RequestFields.GetValues read expects, never one
        //occurrence carrying several space-joined URIs (the AS rejects embedded whitespace in a
        //single occurrence as malformed). Scope and authorization_details are forwarded only when
        //supplied; a scope of white space only holds no scope-token (RFC 6749 section 3.3) and is no scope.
        foreach(string resource in options.Resource)
        {
            form.Add(OAuthRequestParameterNames.Resource, resource);
        }

        if(!string.IsNullOrWhiteSpace(options.Scope))
        {
            form[OAuthRequestParameterNames.Scope] = options.Scope;
        }

        if(!string.IsNullOrEmpty(options.AuthorizationDetails))
        {
            form[OAuthRequestParameterNames.AuthorizationDetails] = options.AuthorizationDetails;
        }

        if(EvaluateOutboundPolicy(tokenEndpoint, context, infrastructure) is OAuthOutboundFetchPolicyDenied mintPolicyDenial)
        {
            return Result<TokenResponse, OAuthParseError>.Failure(mintPolicyDenial);
        }

        //RFC 9449 §8.1's retry re-sends this SAME request; attaching the client assertion per attempt
        //(rather than once before the first send) gives the retry a fresh jti/iat instead of the
        //assertion the challenged attempt already presented — see
        //TokenEndpointClientOperations.SendWithDpopRetryAsync's remarks.
        HttpResponseData response = await TokenEndpointClientOperations.SendWithDpopRetryAsync(
            infrastructure, tokenEndpoint, form,
            (attemptNow, ct) => AttachAssertionAsync(
                form, registration, tokenEndpoint, credential.Value, options.ClientAssertion, infrastructure, attemptNow, context, ct),
            context, cancellationToken).ConfigureAwait(false);

        return infrastructure.ParseTokenResponseAsync(response, now);
    }


    /// <summary>
    /// Redeems an ID-JAG: a JWT Bearer grant (§4.4) presenting the grant as the <c>assertion</c> to the
    /// Resource Authorization Server's token endpoint, authenticated with the client assertion the registration's method
    /// names. The returned token response carries the issued access token; a credential the registration cannot form is
    /// the <see cref="OAuthClientAssertionRefused"/> failure, before any send.
    /// </summary>
    public static async ValueTask<Result<TokenResponse, OAuthParseError>> RedeemAsync(
        IdJagRedeemOptions options,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        var credential = ResolveCredential(registration, options.ClientAssertion);

        if(!credential.IsSuccess)
        {
            return Result<TokenResponse, OAuthParseError>.Failure(credential.Error);
        }

        AuthorizationServerMetadataResolution resolution = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

        if(resolution is not AuthorizationServerMetadataResolved resolved)
        {
            return Result<TokenResponse, OAuthParseError>.Failure(
                BuildAuthorizationServerMetadataResolutionFailure(resolution));
        }

        AuthorizationServerMetadata metadata = resolved.Metadata;
        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        Uri tokenEndpoint = metadata.TokenEndpoint!;

        OutgoingFormFields form = new(capacity: 5)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.Assertion] = options.Assertion
        };

        if(EvaluateOutboundPolicy(tokenEndpoint, context, infrastructure) is OAuthOutboundFetchPolicyDenied redeemPolicyDenial)
        {
            return Result<TokenResponse, OAuthParseError>.Failure(redeemPolicyDenial);
        }

        //RFC 9449 §8.1's retry re-sends this SAME request; attaching the client assertion per attempt
        //(rather than once before the first send) gives the retry a fresh jti/iat instead of the
        //assertion the challenged attempt already presented — see
        //TokenEndpointClientOperations.SendWithDpopRetryAsync's remarks.
        HttpResponseData response = await TokenEndpointClientOperations.SendWithDpopRetryAsync(
            infrastructure, tokenEndpoint, form,
            (attemptNow, ct) => AttachAssertionAsync(
                form, registration, tokenEndpoint, credential.Value, options.ClientAssertion, infrastructure, attemptNow, context, ct),
            context, cancellationToken).ConfigureAwait(false);

        return infrastructure.ParseTokenResponseAsync(response, now);
    }


    /// <summary>
    /// Forms the credential the exchange's client assertion is composed under from the registration's method and key
    /// material and the assertion's inputs (<see cref="ClientAssertionCredential.Of"/>), before anything is resolved or
    /// sent: a registration naming a method that presents no assertion, carrying no key, or whose key the inputs cannot
    /// form is the typed <see cref="OAuthClientAssertionRefused"/> failure both flows return.
    /// </summary>
    /// <param name="registration">The registration naming the method and carrying the key or the secret.</param>
    /// <param name="clientAssertion">The assertion's inputs.</param>
    /// <returns>The credential, or the refusal.</returns>
    private static Result<ClientAssertionCredential, OAuthParseError> ResolveCredential(
        ClientRegistration registration, ClientAssertionOptions clientAssertion)
    {
        ArgumentNullException.ThrowIfNull(clientAssertion);

        var credential = ClientAssertionCredential.Of(registration, clientAssertion);

        if(credential.IsSuccess)
        {
            return Result<ClientAssertionCredential, OAuthParseError>.Success(credential.Value);
        }

        return Result<ClientAssertionCredential, OAuthParseError>.Failure(new OAuthClientAssertionRefused(
            credential.Error,
            new DecisionSupport(credential.Error.Describe())
            {
                SpecificationReference = "RFC 7523 §2.2"
            }));
    }


    /// <summary>
    /// Attaches one attempt's client assertion, composed fresh under the formed credential, to the exchange's form.
    /// </summary>
    /// <param name="form">The exchange's form.</param>
    /// <param name="registration">The registration choosing the assertion's audience and type.</param>
    /// <param name="tokenEndpoint">The token endpoint the form is sent to.</param>
    /// <param name="credential">The credential <see cref="ResolveCredential"/> formed.</param>
    /// <param name="clientAssertion">The assertion's serialisers and validity window.</param>
    /// <param name="infrastructure">The client infrastructure.</param>
    /// <param name="now">The instant of this attempt.</param>
    /// <param name="context">The per-operation exchange context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>No header fields: the assertion travels in the form.</returns>
    private static async ValueTask<OutgoingHeaders> AttachAssertionAsync(
        OutgoingFormFields form,
        ClientRegistration registration,
        Uri tokenEndpoint,
        ClientAssertionCredential credential,
        ClientAssertionOptions clientAssertion,
        OAuthClientInfrastructure infrastructure,
        DateTimeOffset now,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        await ClientTokenEndpointAuthentication.AttachClientAssertionAsync(
            form, registration, tokenEndpoint, credential,
            clientAssertion.HeaderSerializer, clientAssertion.PayloadSerializer, clientAssertion.ClientAssertionLifetime,
            infrastructure, now, context, cancellationToken).ConfigureAwait(false);

        return OutgoingHeaders.Empty;
    }


    /// <summary>
    /// Evaluates <paramref name="target"/> against <paramref name="context"/>'s
    /// <see cref="OutboundFetchPolicy"/> (falling back to <paramref name="infrastructure"/>'s
    /// deployment default) before a client-side dial to the token endpoint named by resolved
    /// authorization-server metadata — the same SSRF-hardening class as the AuthCode PAR and token
    /// sends, since the token endpoint is likewise read out of a discovered document rather than
    /// chosen by this library.
    /// </summary>
    /// <param name="target">The token endpoint the flow is about to dial.</param>
    /// <param name="context">The per-operation exchange context carrying the policy.</param>
    /// <param name="infrastructure">
    /// Supplies <see cref="OAuthClientInfrastructure.OutboundFetchPolicy"/>, the deployment
    /// default applied when <paramref name="context"/> carries none.
    /// </param>
    /// <returns>
    /// <see langword="null"/> when <paramref name="target"/> is allowed; otherwise the typed
    /// denial to return from <see cref="MintAsync"/> or <see cref="RedeemAsync"/>.
    /// </returns>
    private static OAuthOutboundFetchPolicyDenied? EvaluateOutboundPolicy(
        Uri target, ExchangeContext context, OAuthClientInfrastructure infrastructure)
    {
        OutboundFetchPolicy policy = context.ResolveOutboundFetchPolicy(infrastructure.OutboundFetchPolicy);
        OutboundFetchDecision decision = policy.Evaluate(target);

        if(decision.IsAllowed)
        {
            return null;
        }

        ActivityTagsCollection tags = new()
        {
            [OAuthEventNames.OutboundFetchPolicyDenialReasonTagName] = decision.DenyReason,
            [OAuthEventNames.OutboundFetchPolicyDenialEndpointTagName] = target.ToString()
        };

        _ = (Activity.Current?.AddEvent(new ActivityEvent(OAuthEventNames.OutboundFetchPolicyDenied, tags: tags)));

        return new OAuthOutboundFetchPolicyDenied(
            target,
            decision.DenyReason!,
            new DecisionSupport("The token endpoint was refused by the outbound fetch policy.")
            {
                SpecificationReference = "RFC 8707 §2"
            });
    }


    /// <summary>
    /// Preserves the complete typed resolution failure for the in-process caller of this exchange.
    /// </summary>
    private static OAuthAuthorizationServerMetadataUnresolved BuildAuthorizationServerMetadataResolutionFailure(
        AuthorizationServerMetadataResolution resolution) =>
        new(
            resolution,
            new DecisionSupport("The authorization server metadata required for this exchange did not resolve.")
            {
                SpecificationReference = "RFC 8414 §3"
            });
}
