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
    /// <remarks>
    /// The mint's token response stands whatever its <c>token_type</c> when DPoP is wired: the issued token is an
    /// ID-JAG, never an access token, so the discard of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>, which binds "the access
    /// token response", does not apply to it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">RFC 8693 Section 2.2.1</see>: "If the issued
    /// token is not an access token or usable as an access token, then the "token_type" value "N_A" is used to indicate
    /// that an OAuth 2.0 "token_type" identifier is not applicable in that context."
    /// </remarks>
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

        //The request carries the subject token and the signed client assertion; a redirect followed would
        //re-send both to the origin its Location field names (RFC 9110 Section 15.4.8).
        if(CredentialBearingRedirect.Refuse(tokenEndpoint, response) is OAuthRedirectRefused mintRedirectRefusal)
        {
            return Result<TokenResponse, OAuthParseError>.Failure(mintRedirectRefusal);
        }

        return infrastructure.ParseTokenResponseAsync(response, now);
    }


    /// <summary>
    /// Redeems an ID-JAG: a JWT Bearer grant (§4.4) presenting the grant as the <c>assertion</c> to the
    /// Resource Authorization Server's token endpoint, authenticated with a <c>private_key_jwt</c> client
    /// assertion. The returned token response carries the issued access token; with DPoP wired and
    /// <see cref="OAuthClientInfrastructure.RequiresDpopTokenType"/> set, a token response naming a
    /// <c>token_type</c> other than <c>DPoP</c> fails with an <see cref="OAuthInvalidFieldValue"/> naming
    /// <c>token_type</c> (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>).
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

        //The request carries the ID-JAG and the signed client assertion; a redirect followed would re-send
        //both to the origin its Location field names (RFC 9110 Section 15.4.8).
        if(CredentialBearingRedirect.Refuse(tokenEndpoint, response) is OAuthRedirectRefused redeemRedirectRefusal)
        {
            return Result<TokenResponse, OAuthParseError>.Failure(redeemRedirectRefusal);
        }

        Result<TokenResponse, OAuthParseError> redeemResult = infrastructure.ParseTokenResponseAsync(response, now);
        if(!redeemResult.IsSuccess)
        {
            return redeemResult;
        }

        //RFC 9449 Section 5: the JWT bearer grant is an access token request, so its token response naming a
        //token_type other than DPoP is discarded when the protection is deemed important.
        return TokenEndpointClientOperations.RefuseTokenTypeOtherThanDpop(infrastructure, redeemResult.Value) switch
        {
            OAuthInvalidFieldValue tokenTypeRefusal => Result<TokenResponse, OAuthParseError>.Failure(tokenTypeRefusal),
            _ => redeemResult
        };
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
