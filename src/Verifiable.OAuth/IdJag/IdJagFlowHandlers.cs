using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// Drives the two client-side ID-JAG token-endpoint exchanges of
/// draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.3 (mint) and §4.4 (redeem) over the injected
/// transport. Both authenticate the confidential client (§9.1) with a <c>private_key_jwt</c> client
/// assertion (RFC 7523 §2.2) and parse the response through the infrastructure's token-response parser.
/// </summary>
public static class IdJagFlowHandlers
{
    /// <summary>
    /// Mints an ID-JAG: a Token Exchange (<c>requested_token_type</c> id-jag, §4.3) to the IdP's token
    /// endpoint, authenticated with a <c>private_key_jwt</c> client assertion. The returned token response
    /// carries the ID-JAG in its <see cref="TokenResponse.AccessToken"/> (<c>token_type</c> N_A, §4.3.4).
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

        AuthorizationServerMetadataResolution resolution = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

        if(!resolution.IsResolved)
        {
            return Result<TokenResponse, OAuthParseError>.Failure(
                BuildAuthorizationServerMetadataResolutionFailure(resolution));
        }

        AuthorizationServerMetadata metadata = resolution.Metadata!;
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

        //§4.3 / RFC 8707 §2.1.1: each requested resource becomes its OWN repeated resource occurrence
        //on the wire (OutgoingFormFields.Add) — the genuine RFC 8707 multi-resource wire form the
        //authorization server's own ReadResource/RequestFields.GetValues read expects, never one
        //occurrence carrying several space-joined URIs (the AS now rejects embedded whitespace in a
        //single occurrence as malformed). Scope and authorization_details are forwarded only when supplied.
        foreach(string resource in options.Resource)
        {
            form.Add(OAuthRequestParameterNames.Resource, resource);
        }

        if(!string.IsNullOrEmpty(options.Scope))
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

        //RFC 9449 §8.1's retry re-sends this SAME request; attaching the private_key_jwt client
        //assertion per attempt (rather than once before the first send) gives the retry a fresh
        //jti/iat instead of the assertion the challenged attempt already presented — see
        //TokenEndpointClientOperations.SendWithDpopRetryAsync's remarks.
        HttpResponseData response = await TokenEndpointClientOperations.SendWithDpopRetryAsync(
            infrastructure, tokenEndpoint, form,
            async (attemptNow, ct) =>
            {
                await ClientTokenEndpointAuthentication.AttachClientAssertionAsync(
                    form, registration, tokenEndpoint, options.SigningKey, options.SigningKeyId,
                    options.HeaderSerializer, options.PayloadSerializer, options.ClientAssertionLifetime,
                    infrastructure, attemptNow, context, ct).ConfigureAwait(false);

                return OutgoingHeaders.Empty;
            },
            context, cancellationToken).ConfigureAwait(false);

        return infrastructure.ParseTokenResponseAsync(response, now);
    }


    /// <summary>
    /// Redeems an ID-JAG: a JWT Bearer grant (§4.4) presenting the grant as the <c>assertion</c> to the
    /// Resource Authorization Server's token endpoint, authenticated with a <c>private_key_jwt</c> client
    /// assertion. The returned token response carries the issued access token.
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

        AuthorizationServerMetadataResolution resolution = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

        if(!resolution.IsResolved)
        {
            return Result<TokenResponse, OAuthParseError>.Failure(
                BuildAuthorizationServerMetadataResolutionFailure(resolution));
        }

        AuthorizationServerMetadata metadata = resolution.Metadata!;
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

        //RFC 9449 §8.1's retry re-sends this SAME request; attaching the private_key_jwt client
        //assertion per attempt (rather than once before the first send) gives the retry a fresh
        //jti/iat instead of the assertion the challenged attempt already presented — see
        //TokenEndpointClientOperations.SendWithDpopRetryAsync's remarks.
        HttpResponseData response = await TokenEndpointClientOperations.SendWithDpopRetryAsync(
            infrastructure, tokenEndpoint, form,
            async (attemptNow, ct) =>
            {
                await ClientTokenEndpointAuthentication.AttachClientAssertionAsync(
                    form, registration, tokenEndpoint, options.SigningKey, options.SigningKeyId,
                    options.HeaderSerializer, options.PayloadSerializer, options.ClientAssertionLifetime,
                    infrastructure, attemptNow, context, ct).ConfigureAwait(false);

                return OutgoingHeaders.Empty;
            },
            context, cancellationToken).ConfigureAwait(false);

        return infrastructure.ParseTokenResponseAsync(response, now);
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
    /// Builds the <see cref="OAuthAuthorizationServerMetadataUnresolved"/> failure for a non-
    /// <see cref="AuthorizationServerMetadataResolutionOutcome.Resolved"/> <paramref name="resolution"/>,
    /// carrying the outcome and the resolver's internal
    /// <see cref="AuthorizationServerMetadataResolution.Defect"/> as
    /// <see cref="DecisionSupport.LikelyCause"/> — safe here since this Result is consumed
    /// in-process by the calling application rather than serialized onto an outbound wire response.
    /// </summary>
    private static OAuthAuthorizationServerMetadataUnresolved BuildAuthorizationServerMetadataResolutionFailure(
        AuthorizationServerMetadataResolution resolution) =>
        new(
            resolution.Outcome,
            new DecisionSupport("The authorization server metadata required for this exchange did not resolve.")
            {
                LikelyCause = resolution.Defect,
                SpecificationReference = "RFC 8414 §3"
            });
}
