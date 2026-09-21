using Verifiable.Core;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.ClientCredentials;

/// <summary>
/// The pure static handler function backing <see cref="ClientCredentialsClient.RequestTokenAsync"/>.
/// No instance state is held; every I/O delegate comes from the caller's
/// <see cref="OAuthClientInfrastructure"/>.
/// </summary>
internal static class ClientCredentialsFlowHandlers
{
    /// <summary>
    /// Handles a <c>client_credentials</c> token request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4.2">RFC 6749 §4.4.2</see>:
    /// resolves and validates the authorization server metadata exactly as the Authorization Code
    /// token leg does (<see cref="TokenEndpointClientOperations.ResolveValidatedAuthorizationServerMetadataAsync"/>),
    /// composes the request body, attaches confidential-client authentication by
    /// <see cref="ClientRegistration.AuthenticationMethod"/>
    /// (<see cref="TokenEndpointClientOperations.AttachClientAuthenticationAsync"/>), and sends
    /// through the same DPoP-retrying token request
    /// (<see cref="TokenEndpointClientOperations.SendTokenRequestWithDpopRetryAsync"/>) the
    /// Authorization Code token leg uses.
    /// </summary>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="scope">The requested scope, or <see langword="null"/> to request the AS's default.</param>
    /// <param name="resource">
    /// The RFC 8707 §2 <c>resource</c> indicator(s) to request, each becoming its own repeated
    /// occurrence on the wire (<see cref="TokenEndpointClientOperations.AddResourceOccurrences"/>).
    /// <see langword="null"/> or empty omits the parameter entirely.
    /// </param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, and time delegates.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport delegate.</param>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2). Required when
    /// <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>; ignored for every other method.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see cref="AuthCodeFlowEndpointOutcome.Ok"/> with the token response fields on success — the
    /// same typed-result shape
    /// <see cref="AuthCodeFlowHandlers.HandleTokenAsync(System.Collections.Generic.IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, ClientAssertionOptions?, CancellationToken)"/>
    /// answers in.
    /// </returns>
    internal static async ValueTask<AuthCodeFlowEndpointResult> HandleTokenRequestAsync(
        ClientRegistration registration,
        string? scope,
        IReadOnlyList<string>? resource,
        OAuthClientInfrastructure infrastructure,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(context);

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await TokenEndpointClientOperations.ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        OutgoingFormFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = registration.ClientId.Value
        };

        if(!string.IsNullOrWhiteSpace(scope))
        {
            tokenFields[OAuthRequestParameterNames.Scope] = scope;
        }

        TokenEndpointClientOperations.AddResourceOccurrences(tokenFields, resource);

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        Result<HttpResponseData, AuthCodeFlowEndpointResult> tokenSendResult =
            await TokenEndpointClientOperations.SendTokenRequestWithDpopRetryAsync(
                infrastructure, metadata.TokenEndpoint!, tokenFields,
                (attemptNow, ct) => TokenEndpointClientOperations.AttachClientAuthenticationAsync(
                    tokenFields, registration, metadata.TokenEndpoint!, clientAssertionOptions,
                    infrastructure, attemptNow, context, ct),
                context, cancellationToken)
                .ConfigureAwait(false);
        if(!tokenSendResult.IsSuccess)
        {
            return tokenSendResult.Error!;
        }

        Result<TokenResponse, OAuthParseError> tokenResult =
            infrastructure.ParseTokenResponseAsync(tokenSendResult.Value, now);

        if(!tokenResult.IsSuccess)
        {
            return TokenEndpointClientOperations.BuildEndpointResultFromParseError(tokenResult.Error!);
        }

        TokenResponse tokenResponse = tokenResult.Value;
        var body = new Dictionary<string, object>
        {
            [OAuthRequestParameterNames.AccessToken] = tokenResponse.AccessToken,
            [OAuthRequestParameterNames.TokenType] = tokenResponse.TokenType,
            [OAuthRequestParameterNames.ExpiresIn] = tokenResponse.ExpiresIn ?? 0,
            [OAuthRequestParameterNames.Scope] = tokenResponse.Scope ?? string.Empty
        };

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.Ok,
            Body = body
        };
    }
}
