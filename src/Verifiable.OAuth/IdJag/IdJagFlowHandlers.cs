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
    /// endpoint, authenticated by the method the registration names - the client assertion of <c>private_key_jwt</c> or
    /// <c>client_secret_jwt</c>, or the client secret of <c>client_secret_basic</c> or <c>client_secret_post</c> the
    /// registration carries for this call (RFC 6749 §2.3.1) - with no <c>audience</c> where
    /// <see cref="IdJagMintOptions.Audience"/> names none. The returned token response carries the ID-JAG in its
    /// <see cref="TokenResponse.AccessToken"/> (<c>token_type</c> N_A, §4.3.4) and is refused where its
    /// <c>issued_token_type</c> is not the ID-JAG's (§4.3.2; RFC 8693 §2.2.1); a credential the registration cannot form is
    /// the <see cref="OAuthClientAssertionRefused"/> or <see cref="OAuthClientAuthenticationRefused"/> failure, before any
    /// send.
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

        var credential = ResolveAuthentication(registration, options.ClientAssertion);

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
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag)
        };

        //RFC 8693 §2.1 makes audience OPTIONAL: a provider taking the audience from its own mapping of the resource is sent none.
        if(options.Audience is { } audience)
        {
            form[OAuthRequestParameterNames.Audience] = audience;
        }

        form[OAuthRequestParameterNames.SubjectToken] = options.SubjectToken;
        form[OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(options.SubjectTokenType);

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

        //RFC 8693 §2.1: an actor_token is sent with its actor_token_type, which is "REQUIRED when the actor_token parameter is
        //present".
        if(options.Actor is { } actor)
        {
            form[OAuthRequestParameterNames.ActorToken] = actor.Token;
            form[OAuthRequestParameterNames.ActorTokenType] = TokenTypeNames.GetName(actor.Type);
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
            (attemptNow, ct) => TokenEndpointClientOperations.AttachClientAuthenticationAsync(
                form, registration, tokenEndpoint, credential.Value, options.ClientAssertion, infrastructure, attemptNow, context, ct),
            context, cancellationToken).ConfigureAwait(false);

        var minted = infrastructure.ParseTokenResponseAsync(response, now);

        //Draft-04 §4.3.2 and RFC 8693 §2.2.1: the answer names the type of the token issued, and a token of another type than
        //the ID-JAG asked for is no grant this flow presents.
        if(minted.IsSuccess
            && (minted.Value.IssuedTokenType is not { } issued || !WellKnownTokenTypeIdentifiers.IsIdJag(issued)))
        {
            return Result<TokenResponse, OAuthParseError>.Failure(new OAuthInvalidFieldValue(
                OAuthRequestParameterNames.IssuedTokenType,
                minted.Value.IssuedTokenType ?? string.Empty,
                "The token exchange answered a token of another type than the identity assertion grant it asked for.",
                new DecisionSupport("The identity provider's answer names another issued_token_type than the ID-JAG's.")
                {
                    SpecificationReference = "draft-ietf-oauth-identity-assertion-authz-grant-04 §4.3.2"
                }));
        }

        return minted;
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
    /// Forms the client authentication a mint presents, before anything is resolved or sent, by the method the registration
    /// names: for <c>client_secret_basic</c> and <c>client_secret_post</c> no assertion credential, the secret the registration
    /// carries for this call being presented as it is (RFC 6749 §2.3.1), and a registration carrying none refused; for every
    /// other method the assertion credential <see cref="ResolveCredential"/> forms, an assertion method handed no inputs
    /// refused, and a method presenting neither a secret nor an assertion refused as the assertion's credential refuses it.
    /// </summary>
    /// <param name="registration">The registration naming the method and carrying the key or the secret.</param>
    /// <param name="clientAssertion">The assertion's inputs, or <see langword="null"/> for a secret method.</param>
    /// <returns>The assertion credential, <see langword="null"/> for a secret method, or the refusal.</returns>
    private static Result<ClientAssertionCredential?, OAuthParseError> ResolveAuthentication(
        ClientRegistration registration, ClientAssertionOptions? clientAssertion)
    {
        var method = registration.AuthenticationMethod;
        var presentsSecret = method.Code == ClientAuthenticationMethod.ClientSecretBasic.Code
            || method.Code == ClientAuthenticationMethod.ClientSecretPost.Code;

        if(presentsSecret)
        {
            return registration.AuthenticationKeyMaterial?.PrivateKey is not null
                ? Result<ClientAssertionCredential?, OAuthParseError>.Success(null)
                : Result<ClientAssertionCredential?, OAuthParseError>.Failure(new OAuthClientAuthenticationRefused(
                    method,
                    ClientAuthenticationRefusalReason.ClientSecretNotCarried,
                    new DecisionSupport("The registration names a client secret method and carries no client secret.")
                    {
                        SpecificationReference = "RFC 6749 §2.3.1"
                    }));
        }

        if(clientAssertion is null)
        {
            var presentsAssertion = method.Code == ClientAuthenticationMethod.PrivateKeyJwt.Code
                || method.Code == ClientAuthenticationMethod.ClientSecretJwt.Code;

            if(presentsAssertion)
            {
                return Result<ClientAssertionCredential?, OAuthParseError>.Failure(new OAuthClientAuthenticationRefused(
                    method,
                    ClientAuthenticationRefusalReason.AssertionInputsNotGiven,
                    new DecisionSupport("The registration names a client assertion method and the mint was handed no assertion inputs.")
                    {
                        SpecificationReference = "RFC 7523 §2.2"
                    }));
            }

            var refusal = new ClientAssertionCredentialRefusal
            {
                Reason = ClientAssertionCredentialRefusalReason.MethodPresentsNoAssertion,
                Method = method
            };

            return Result<ClientAssertionCredential?, OAuthParseError>.Failure(new OAuthClientAssertionRefused(
                refusal,
                new DecisionSupport(refusal.Describe())
                {
                    SpecificationReference = "RFC 7523 §2.2"
                }));
        }

        var credential = ResolveCredential(registration, clientAssertion);

        return credential.IsSuccess
            ? Result<ClientAssertionCredential?, OAuthParseError>.Success(credential.Value)
            : Result<ClientAssertionCredential?, OAuthParseError>.Failure(credential.Error);
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
