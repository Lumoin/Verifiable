using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// Drives the two client-side ID-JAG token-endpoint exchanges of
/// draft-ietf-oauth-identity-assertion-authz-grant §4.3 (mint) and §4.4 (redeem) over the injected
/// transport. Both authenticate the confidential client (§9.1) with a <c>private_key_jwt</c> client
/// assertion (RFC 7523 §2.2) and parse the response through the infrastructure's token-response parser.
/// </summary>
[DebuggerDisplay("IdJagFlowHandlers")]
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

        AuthorizationServerMetadata metadata = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);
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

        //§4.3: the requested resource (RFC 8707 — repeated values collapse to one space-delimited field
        //the AS skin re-splits), scope, and authorization_details are forwarded only when supplied.
        if(options.Resource.Count > 0)
        {
            form[OAuthRequestParameterNames.Resource] = string.Join(' ', options.Resource);
        }

        if(!string.IsNullOrEmpty(options.Scope))
        {
            form[OAuthRequestParameterNames.Scope] = options.Scope;
        }

        if(!string.IsNullOrEmpty(options.AuthorizationDetails))
        {
            form[OAuthRequestParameterNames.AuthorizationDetails] = options.AuthorizationDetails;
        }

        await AttachClientAssertionAsync(
            form, registration, tokenEndpoint, options.SigningKey, options.SigningKeyId,
            options.HeaderSerializer, options.PayloadSerializer, options.ClientAssertionLifetime,
            infrastructure, now, context, cancellationToken).ConfigureAwait(false);

        HttpResponseData response = await infrastructure.SendFormPostAsync(
            tokenEndpoint, form, OutgoingHeaders.Empty, context, cancellationToken).ConfigureAwait(false);

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

        AuthorizationServerMetadata metadata = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);
        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        Uri tokenEndpoint = metadata.TokenEndpoint!;

        OutgoingFormFields form = new(capacity: 5)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.Assertion] = options.Assertion
        };

        await AttachClientAssertionAsync(
            form, registration, tokenEndpoint, options.SigningKey, options.SigningKeyId,
            options.HeaderSerializer, options.PayloadSerializer, options.ClientAssertionLifetime,
            infrastructure, now, context, cancellationToken).ConfigureAwait(false);

        HttpResponseData response = await infrastructure.SendFormPostAsync(
            tokenEndpoint, form, OutgoingHeaders.Empty, context, cancellationToken).ConfigureAwait(false);

        return infrastructure.ParseTokenResponseAsync(response, now);
    }


    /// <summary>
    /// Adds the confidential-client authentication parameters — <c>client_id</c>,
    /// <c>client_assertion_type</c>, and a freshly-signed <c>private_key_jwt</c> <c>client_assertion</c>
    /// (RFC 7523 §2.2) bound to the token endpoint — to a token-endpoint request form.
    /// </summary>
    private static async ValueTask AttachClientAssertionAsync(
        OutgoingFormFields form,
        ClientRegistration registration,
        Uri tokenEndpoint,
        PrivateKeyMemory signingKey,
        string signingKeyId,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        TimeSpan clientAssertionLifetime,
        OAuthClientInfrastructure infrastructure,
        DateTimeOffset now,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        string jti = await infrastructure.GenerateIdentifierAsync(
            WellKnownIdentifierPurposes.OAuthJti, context, cancellationToken).ConfigureAwait(false);

        string clientAssertion = await ClientAssertionSigning.SignAsync(
            registration.ClientId.Value,
            tokenEndpoint.OriginalString,
            jti,
            now,
            now.Add(clientAssertionLifetime),
            signingKey,
            signingKeyId,
            headerSerializer,
            payloadSerializer,
            infrastructure.Base64UrlEncoder,
            infrastructure.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        form[OAuthRequestParameterNames.ClientId] = registration.ClientId.Value;
        form[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
        form[OAuthRequestParameterNames.ClientAssertion] = clientAssertion;
    }
}
