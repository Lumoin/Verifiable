using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Validation;
using Verifiable.Server;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Pure static handler functions for the OAuth 2.0 Authorization Code flow.
/// </summary>
/// <remarks>
/// <para>
/// Each handler takes the inbound request fields, the long-lived
/// <see cref="OAuthClientInfrastructure"/>, the per-call
/// <see cref="ClientRegistration"/>, and a cancellation token. No instance
/// state is held. The application author wires these to HTTP routes and
/// supplies the infrastructure constructed at startup plus the registration
/// loaded for the current request.
/// </para>
/// <para>
/// Typical ASP.NET wiring (application code, not part of this library):
/// </para>
/// <code>
/// OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create( ... );
/// ClientRegistration registration = LoadFromStore(clientId);
/// var group = app.MapGroup("/oauth");
/// group.MapPost(AuthCodeFlowRoutes.Par,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleParAsync(fields, infrastructure, registration, ct));
/// group.MapGet(AuthCodeFlowRoutes.Callback,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleCallbackAsync(fields, infrastructure, registration, ct));
/// group.MapPost(AuthCodeFlowRoutes.Token,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleTokenAsync(fields, infrastructure, registration, ct));
/// group.MapPost(AuthCodeFlowRoutes.Revocation,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleRevocationAsync(fields, infrastructure, registration, ct));
/// </code>
/// <para>
/// In-memory state store for development and testing:
/// </para>
/// <code>
/// var store = new Dictionary&lt;string, FlowState&gt;();
/// OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
///     ...
///     saveStateAsync: (state, _) => { store[state.FlowId] = state; return ValueTask.CompletedTask; },
///     loadStateAsync: (id, _)    => ValueTask.FromResult(store.GetValueOrDefault(id)),
///     ...);
/// </code>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of disposable state records is transferred to SaveStateAsync on success. The nullable-with-finally pattern ensures disposal on all failure paths.")]
public static class AuthCodeFlowHandlers
{
    //Convenience overloads for single-tenant callers that ignore tenancy: each
    //drives its handler over a fresh empty ExchangeContext. Multi-tenant
    //deployments call the ExchangeContext-bearing overloads directly so the
    //transport and flow-state delegates can scope per tenant.

    /// <inheritdoc cref="HandleParAsync(IReadOnlyDictionary{string, string}, Uri, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleParAsync(
        IReadOnlyDictionary<string, string> fields,
        Uri redirectUri,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleParAsync(fields, redirectUri, infrastructure, registration, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="HandleCallbackAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleCallbackAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleCallbackAsync(fields, infrastructure, registration, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="HandleTokenAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleTokenAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleTokenAsync(fields, infrastructure, registration, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="HandleRevocationAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleRevocationAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleRevocationAsync(fields, infrastructure, registration, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="RefreshAsync(RefreshTokenRequest, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        RefreshTokenRequest request,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        RefreshAsync(request, infrastructure, registration, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="HandleJarParAsync(AuthCodeStartJarParOptions, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleJarParAsync(
        AuthCodeStartJarParOptions jarOptions,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleJarParAsync(jarOptions, infrastructure, registration, new ExchangeContext(), cancellationToken);


    /// <inheritdoc cref="HandleJarAuthorizeAsync(AuthCodeStartJarAuthorizeOptions, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleJarAuthorizeAsync(
        AuthCodeStartJarAuthorizeOptions jarOptions,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        HandleJarAuthorizeAsync(jarOptions, infrastructure, registration, new ExchangeContext(), cancellationToken);


    /// <summary>
    /// Handles a pushed authorization request. Generates PKCE parameters, POSTs to
    /// the PAR endpoint, persists <see cref="ParCompletedState"/> state, and returns a
    /// redirect URI for the caller to forward to the user agent.
    /// </summary>
    /// <param name="fields">
    /// Inbound form fields. May include <c>scope</c>; other required values are
    /// taken from <paramref name="registration"/>.
    /// </param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see cref="AuthCodeFlowEndpointOutcome.Redirect"/> on success with
    /// <see cref="AuthCodeFlowEndpointResult.RedirectUri"/> set to the authorization
    /// endpoint URI including the PAR <c>request_uri</c>.
    /// </returns>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleParAsync(
        IReadOnlyDictionary<string, string> fields,
        Uri redirectUri,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error!;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        string state = GenerateEntropyHexString(infrastructure);

        PkceParameters pkce = GeneratePkceParameters(infrastructure.Base64UrlEncoder);

        ImmutableArray<string> scopes = fields.TryGetValue(OAuthRequestParameterNames.Scope, out string? scopeValue)
            ? [.. scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries)]
            : [WellKnownScopes.OpenId];

        var parBody = new ParRequestBody
        {
            ClientId = registration.ClientId.Value,
            CodeChallenge = pkce.EncodedChallenge,
            CodeChallengeMethod = pkce.Method,
            RedirectUri = redirectUri,
            Scopes = scopes,
            State = state
        };

        OutgoingFormFields formFields = EncodeParRequestBody(parBody);

        HttpResponseData parHttpResponse;
        try
        {
            parHttpResponse = await infrastructure.SendFormPostAsync(
                metadata.PushedAuthorizationRequestEndpoint!,
                formFields,
                OutgoingHeaders.Empty,
                context,
                cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex)
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.InternalError,
                ErrorCode = "server_error",
                ErrorDescription = ex.Message
            };
        }

        Result<ParResponse, OAuthParseError> parResult =
            infrastructure.ParseParResponseAsync(parHttpResponse);

        if(!parResult.IsSuccess)
        {
            return BuildEndpointResultFromParseError(parResult.Error!);
        }

        ParResponse parResponse = parResult.Value;
        ParCompletedState parCompleted = new ParCompletedState
        {
            FlowId = state,
            ExpectedIssuer = registration.AuthorizationServerIssuer.OriginalString,
            EnteredAt = now,
            ExpiresAt = now.AddSeconds(parResponse.ExpiresIn),
            Kind = FlowKind.AuthCodeClient,
            Pkce = pkce,
            RedirectUri = redirectUri,
            Scopes = scopes,
            Par = parResponse
        };

        await infrastructure.SaveStateAsync(parCompleted, context, cancellationToken).ConfigureAwait(false);

        Uri authorizationUri = BuildAuthorizationRedirectUri(
            metadata.AuthorizationEndpoint!,
            registration.ClientId.Value,
            parResponse.RequestUri);

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.Redirect,
            RedirectUri = authorizationUri
        };
    }


    /// <summary>
    /// Handles the authorization server callback. Loads the flow state by the
    /// <c>state</c> parameter, runs the profile-specific validation rules, and
    /// persists <see cref="AuthorizationCodeReceivedState"/> state ready for token exchange.
    /// </summary>
    /// <param name="fields">
    /// The callback query parameters. Must include <c>code</c> and <c>state</c>.
    /// HAIP 1.0 additionally requires <c>iss</c>.
    /// </param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleCallbackAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error!;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        //RFC 6749 §4.1.2.1 Authorization Error Response — error is present instead of code.
        //RFC 9207 §2.4/§4: "clients MUST NOT assume that the error originates from the
        //intended authorization server," so a PRESENT iss on this branch is validated with
        //the same mix-up-attack rule the success path applies before the error is trusted.
        if(fields.TryGetValue(OAuthRequestParameterNames.Error, out string? errorCode))
        {
            return await BuildCallbackErrorResultAsync(
                fields, infrastructure, context, errorCode, cancellationToken).ConfigureAwait(false);
        }

        if(!fields.TryGetValue(OAuthRequestParameterNames.Code, out string? code) ||
           !fields.TryGetValue(OAuthRequestParameterNames.State, out string? state))
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "Missing required callback parameters."
            };
        }

        FlowState? loaded = await infrastructure.LoadStateAsync(
            state, context, cancellationToken).ConfigureAwait(false);

        if(loaded is not ParCompletedState parCompleted)
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "No active flow found for the supplied state value."
            };
        }

        //Client-side flow does not sit inside server dispatch, so there is no
        //resolved per-request policy context to thread in. An empty
        //ExchangeContext satisfies the required-field contract and keeps
        //policy reads on the client-side validators returning library
        //defaults (the strict reading) — which is the intended behaviour for
        //out-of-dispatch validators.
        ValidationContext validationContext = new()
        {
            Context = new ExchangeContext(),
            Fields = fields,
            FlowState = parCompleted,
            TimeProvider = infrastructure.TimeProvider,
            Now = infrastructure.TimeProvider.GetUtcNow()
        };

        ClaimIssuer<ValidationContext> callbackValidator =
            infrastructure.ResolveCallbackValidator(registration, infrastructure.TimeProvider);

        ClaimIssueResult validationResult = await callbackValidator.GenerateClaimsAsync(
            validationContext, parCompleted.FlowId, cancellationToken).ConfigureAwait(false);

        if(!validationResult.IsComplete
            || validationResult.Claims.Any(static c => c.Outcome != ClaimOutcome.Success))
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "Callback validation failed.",
                ValidationClaims = (IReadOnlyList<Claim>)validationResult.Claims
            };
        }

        string? iss = fields.TryGetValue(OAuthRequestParameterNames.Iss, out string? issValue)
            ? issValue
            : null;

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();

        AuthorizationCodeReceivedState codeReceived = new AuthorizationCodeReceivedState
        {
            FlowId = parCompleted.FlowId,
            ExpectedIssuer = parCompleted.ExpectedIssuer,
            EnteredAt = now,
            ExpiresAt = parCompleted.ExpiresAt,
            Kind = FlowKind.AuthCodeClient,
            Code = code,
            State = state,
            IssuerId = iss,
            Pkce = parCompleted.Pkce,
            RedirectUri = parCompleted.RedirectUri
        };

        await infrastructure.SaveStateAsync(codeReceived, context, cancellationToken).ConfigureAwait(false);

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.Ok,
            Body = new Dictionary<string, object> { [AuthCodeFlowRoutes.FlowIdField] = codeReceived.FlowId }
        };
    }


    /// <inheritdoc cref="HandleTokenAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, ClientAssertionOptions?, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> HandleTokenAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        HandleTokenAsync(fields, infrastructure, registration, context, clientAssertionOptions: null, cancellationToken);


    /// <summary>
    /// Handles a token exchange request. Loads the <see cref="AuthorizationCodeReceivedState"/>
    /// state by <c>flow_id</c>, POSTs to the token endpoint with the code, the PKCE verifier, and
    /// the confidential-client authentication <see cref="ClientRegistration.AuthenticationMethod"/>
    /// selects (RFC 6749 §3.2.1 / RFC 7523 §2.2), and persists <see cref="TokenReceivedState"/> state.
    /// </summary>
    /// <param name="fields">
    /// Inbound form fields. Must include <c>flow_id</c> to locate the pending state.
    /// </param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2): the <c>kid</c>,
    /// the header/payload serialisers, and the assertion lifetime. Required when
    /// <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> — the signing key itself is read from
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>. Ignored for every other method.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleTokenAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error!;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        if(!fields.TryGetValue(AuthCodeFlowRoutes.FlowIdField, out string? flowId))
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "Missing required parameter: flow_id."
            };
        }

        FlowState? loaded = await infrastructure.LoadStateAsync(
            flowId, context, cancellationToken).ConfigureAwait(false);

        if(loaded is not AuthorizationCodeReceivedState codeState)
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "No code pending token exchange for the supplied flow_id."
            };
        }

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        if(now > codeState.ExpiresAt)
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "Flow has expired."
            };
        }

        OutgoingFormFields tokenFields = EncodeTokenRequest(
            registration.ClientId.Value,
            codeState.Code,
            codeState.RedirectUri,
            codeState.Pkce);

        OutgoingHeaders authenticationHeaders = await AttachClientAuthenticationAsync(
            tokenFields, registration, metadata.TokenEndpoint!, clientAssertionOptions,
            infrastructure, now, context, cancellationToken).ConfigureAwait(false);

        HttpResponseData tokenHttpResponse = await SendTokenRequestWithDpopRetryAsync(
            infrastructure, metadata.TokenEndpoint!, tokenFields, authenticationHeaders, context, cancellationToken)
            .ConfigureAwait(false);

        Result<TokenResponse, OAuthParseError> tokenResult =
            infrastructure.ParseTokenResponseAsync(tokenHttpResponse, now);

        if(!tokenResult.IsSuccess)
        {
            return BuildEndpointResultFromParseError(tokenResult.Error!);
        }

        TokenResponse tokenResponse = tokenResult.Value;
        var tokenReceived = new TokenReceivedState
        {
            FlowId = codeState.FlowId,
            ExpectedIssuer = codeState.ExpectedIssuer,
            EnteredAt = now,
            ExpiresAt = codeState.ExpiresAt,
            Kind = FlowKind.AuthCodeClient,
            AccessToken = tokenResponse.AccessToken,
            TokenType = tokenResponse.TokenType,
            ExpiresIn = tokenResponse.ExpiresIn,
            RefreshToken = tokenResponse.RefreshToken,
            Scope = tokenResponse.Scope,
            IdToken = tokenResponse.IdToken,
            ReceivedAt = now
        };

        await infrastructure.SaveStateAsync(tokenReceived, context, cancellationToken).ConfigureAwait(false);

        var body = new Dictionary<string, object>
        {
            [OAuthRequestParameterNames.AccessToken] = tokenResponse.AccessToken,
            [OAuthRequestParameterNames.TokenType] = tokenResponse.TokenType,
            [OAuthRequestParameterNames.ExpiresIn] = tokenResponse.ExpiresIn ?? 0,
            [OAuthRequestParameterNames.Scope] = tokenResponse.Scope ?? string.Empty
        };

        //A refresh token MAY be issued on the auth-code exchange (RFC 6749 §5.1, e.g.
        //when offline access is granted). It is parsed and persisted, so surface it to
        //the caller too — mirroring the refresh response below.
        if(tokenResponse.RefreshToken is not null)
        {
            body[OAuthRequestParameterNames.RefreshToken] = tokenResponse.RefreshToken;
        }

        //An OpenID Connect token response carries an ID Token alongside the access
        //token (OpenID Connect Core 1.0 §3.1.3.3). Surface it so an OIDC relying party
        //can read it — e.g. to later pass it as id_token_hint to the end_session endpoint.
        if(tokenResponse.IdToken is not null)
        {
            body[OAuthRequestParameterNames.IdToken] = tokenResponse.IdToken;
        }

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.Ok,
            Body = body
        };
    }


    /// <summary>
    /// Handles a token revocation request. POSTs to the revocation endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009</see>.
    /// </summary>
    /// <param name="fields">
    /// Inbound form fields. Must include <c>token</c>; optionally <c>token_type_hint</c>.
    /// </param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleRevocationAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error!;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        if(metadata.RevocationEndpoint is null)
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "unsupported_token_type",
                ErrorDescription = "This authorization server does not support token revocation."
            };
        }

        if(!fields.TryGetValue(OAuthRequestParameterNames.Token, out string? token))
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "Missing required parameter: token."
            };
        }

        var revocationFields = new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.ClientId] = registration.ClientId.Value,
            [OAuthRequestParameterNames.Token] = token
        };

        if(fields.TryGetValue(OAuthRequestParameterNames.TokenTypeHint, out string? hint))
        {
            revocationFields[OAuthRequestParameterNames.TokenTypeHint] = hint;
        }

        //RFC 7009 §2.2 — the revocation endpoint returns 200 with an empty body on
        //success. The response body is not parsed; transport errors are surfaced via
        //exception from the delegate.
        _ = await infrastructure.SendFormPostAsync(
            metadata.RevocationEndpoint,
            revocationFields,
            OutgoingHeaders.Empty,
            context,
            cancellationToken).ConfigureAwait(false);

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.Ok
        };
    }


    /// <inheritdoc cref="RefreshAsync(RefreshTokenRequest, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, ClientAssertionOptions?, CancellationToken)"/>
    public static ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        RefreshTokenRequest request,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        RefreshAsync(request, infrastructure, registration, context, clientAssertionOptions: null, cancellationToken);


    /// <summary>
    /// Refreshes an access token using a refresh token. Independent of the state
    /// machine — call this when the stored access token has expired. Attaches
    /// confidential-client authentication per <see cref="ClientRegistration.AuthenticationMethod"/>
    /// the same way the code-exchange leg does (<see cref="AttachClientAuthenticationAsync"/>,
    /// RFC 6749 §6, §3.2.1), and — the same way the code-exchange leg does — attaches a DPoP proof
    /// and honours a <c>use_dpop_nonce</c> retry (<see cref="SendTokenRequestWithDpopRetryAsync"/>,
    /// RFC 9449 §8.1) whenever <paramref name="infrastructure"/> is wired for DPoP, so a
    /// DPoP-sender-constrained refresh token redeems the same way a fresh access token does.
    /// </summary>
    /// <param name="request">The refresh request parameters.</param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2). Required when
    /// <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>; ignored for every other method.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        RefreshTokenRequest request,
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

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error!;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        OutgoingFormFields refreshFields = EncodeRefreshRequest(registration.ClientId.Value, request);

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        OutgoingHeaders authenticationHeaders = await AttachClientAuthenticationAsync(
            refreshFields, registration, metadata.TokenEndpoint!, clientAssertionOptions,
            infrastructure, now, context, cancellationToken).ConfigureAwait(false);

        HttpResponseData refreshHttpResponse = await SendTokenRequestWithDpopRetryAsync(
            infrastructure, metadata.TokenEndpoint!, refreshFields, authenticationHeaders, context, cancellationToken)
            .ConfigureAwait(false);

        Result<TokenResponse, OAuthParseError> refreshResult =
            infrastructure.ParseTokenResponseAsync(refreshHttpResponse, now);

        if(!refreshResult.IsSuccess)
        {
            return BuildEndpointResultFromParseError(refreshResult.Error!);
        }

        TokenResponse tokenResponse = refreshResult.Value;
        var body = new Dictionary<string, object>
        {
            [OAuthRequestParameterNames.AccessToken] = tokenResponse.AccessToken,
            [OAuthRequestParameterNames.TokenType] = tokenResponse.TokenType,
            [OAuthRequestParameterNames.ExpiresIn] = tokenResponse.ExpiresIn ?? 0,
            [OAuthRequestParameterNames.RefreshToken] = tokenResponse.RefreshToken ?? string.Empty,
            [OAuthRequestParameterNames.Scope] = tokenResponse.Scope ?? string.Empty
        };

        //A refresh response MAY carry a new ID Token (OpenID Connect Core 1.0 §12.1);
        //surface it when present.
        if(tokenResponse.IdToken is not null)
        {
            body[OAuthRequestParameterNames.IdToken] = tokenResponse.IdToken;
        }

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.Ok,
            Body = body
        };
    }


    /// <summary>
    /// Handles a JAR-bearing Pushed Authorization Request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see> +
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see>. The
    /// client signs a JAR with the AuthCode claims (PKCE challenge, redirect
    /// URI, scope, state, nonce) and POSTs to the PAR endpoint with the outer
    /// <c>client_id</c> + <c>request</c> body fields. Persists
    /// <see cref="ParCompletedState"/> with the PKCE verifier and returns the
    /// authorize redirect URI carrying the issued <c>request_uri</c>.
    /// </summary>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleJarParAsync(
        AuthCodeStartJarParOptions jarOptions,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(jarOptions);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error!;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        cancellationToken.ThrowIfCancellationRequested();

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        string state = GenerateEntropyHexString(infrastructure);
        string nonce = jarOptions.Nonce ?? GenerateEntropyHexString(infrastructure);
        PkceParameters pkce = GeneratePkceParameters(infrastructure.Base64UrlEncoder);

        AuthCodeRequestObject requestObject = BuildJarRequestObject(
            registration, jarOptions, pkce, state, nonce, now);

        string compactJar = await AuthCodeJarSigning.SignAsync(
            requestObject,
            jarOptions.SigningKey,
            jarOptions.SigningKeyId,
            jarOptions.HeaderSerializer,
            jarOptions.PayloadSerializer,
            infrastructure.Base64UrlEncoder,
            jarOptions.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        OutgoingFormFields parBody = new()
        {
            [OAuthRequestParameterNames.ClientId] = registration.ClientId.Value,
            [OAuthRequestParameterNames.Request] = compactJar
        };
        foreach((string key, string value) in jarOptions.AdditionalFields.Fields)
        {
            parBody[key] = value;
        }

        HttpResponseData parHttpResponse;
        try
        {
            parHttpResponse = await infrastructure.SendFormPostAsync(
                metadata.PushedAuthorizationRequestEndpoint!,
                parBody,
                OutgoingHeaders.Empty,
                context,
                cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex)
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.InternalError,
                ErrorCode = "server_error",
                ErrorDescription = ex.Message
            };
        }

        Result<ParResponse, OAuthParseError> parResult =
            infrastructure.ParseParResponseAsync(parHttpResponse);

        if(!parResult.IsSuccess)
        {
            return BuildEndpointResultFromParseError(parResult.Error!);
        }

        ParResponse parResponse = parResult.Value;
        ImmutableArray<string> scopes = [.. jarOptions.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)];
        ParCompletedState parCompleted = new()
        {
            FlowId = state,
            ExpectedIssuer = registration.AuthorizationServerIssuer.OriginalString,
            EnteredAt = now,
            ExpiresAt = now.AddSeconds(parResponse.ExpiresIn),
            Kind = FlowKind.AuthCodeClient,
            Pkce = pkce,
            RedirectUri = jarOptions.RedirectUri,
            Scopes = scopes,
            Par = parResponse
        };

        await infrastructure.SaveStateAsync(parCompleted, context, cancellationToken).ConfigureAwait(false);

        Uri authorizationUri = BuildAuthorizationRedirectUri(
            metadata.AuthorizationEndpoint!,
            registration.ClientId.Value,
            parResponse.RequestUri);

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.Redirect,
            RedirectUri = authorizationUri
        };
    }


    /// <summary>
    /// Handles a JAR-by-value direct authorization per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.1">RFC 9101 §6.1</see>.
    /// The client signs a JAR with the AuthCode claims and the handler builds
    /// a redirect URL carrying <c>request=&lt;compact-jws&gt;</c> alongside
    /// the outer <c>client_id</c>. The PKCE verifier is persisted so the
    /// eventual token exchange can complete.
    /// </summary>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleJarAuthorizeAsync(
        AuthCodeStartJarAuthorizeOptions jarOptions,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(jarOptions);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult> metadataResult =
            await ResolveValidatedAuthorizationServerMetadataAsync(
                infrastructure, registration, context, cancellationToken).ConfigureAwait(false);
        if(!metadataResult.IsSuccess)
        {
            return metadataResult.Error!;
        }

        AuthorizationServerMetadata metadata = metadataResult.Value;

        cancellationToken.ThrowIfCancellationRequested();

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        string state = GenerateEntropyHexString(infrastructure);
        string nonce = jarOptions.Nonce ?? GenerateEntropyHexString(infrastructure);
        PkceParameters pkce = GeneratePkceParameters(infrastructure.Base64UrlEncoder);

        AuthCodeRequestObject requestObject = new()
        {
            ClientId = registration.ClientId.Value,
            ResponseType = WellKnownResponseTypes.Code,
            RedirectUri = jarOptions.RedirectUri,
            Scope = jarOptions.Scope,
            State = state,
            Nonce = nonce,
            CodeChallenge = pkce.EncodedChallenge,
            CodeChallengeMethod = pkce.Method.ToString().ToUpperInvariant(),
            Iat = now,
            Nbf = now,
            Exp = now.Add(jarOptions.JarLifetime),
            Iss = registration.ClientId.Value,
            Aud = registration.AuthorizationServerIssuer.OriginalString
        };

        string compactJar = await AuthCodeJarSigning.SignAsync(
            requestObject,
            jarOptions.SigningKey,
            jarOptions.SigningKeyId,
            jarOptions.HeaderSerializer,
            jarOptions.PayloadSerializer,
            infrastructure.Base64UrlEncoder,
            jarOptions.MemoryPool,
            cancellationToken).ConfigureAwait(false);

        Uri authorizationUri = BuildJarAuthorizeRedirectUri(
            metadata.AuthorizationEndpoint!,
            registration.ClientId.Value,
            compactJar,
            jarOptions.AdditionalFields);

        ImmutableArray<string> scopes = [.. jarOptions.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)];
        ParCompletedState parCompleted = new()
        {
            FlowId = state,
            ExpectedIssuer = registration.AuthorizationServerIssuer.OriginalString,
            EnteredAt = now,
            ExpiresAt = now.Add(jarOptions.JarLifetime),
            Kind = FlowKind.AuthCodeClient,
            Pkce = pkce,
            RedirectUri = jarOptions.RedirectUri,
            Scopes = scopes,
            Par = new ParResponse(authorizationUri, (int)jarOptions.JarLifetime.TotalSeconds)
        };

        await infrastructure.SaveStateAsync(parCompleted, context, cancellationToken).ConfigureAwait(false);

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.Redirect,
            RedirectUri = authorizationUri
        };
    }


    private static AuthCodeRequestObject BuildJarRequestObject(
        ClientRegistration registration,
        AuthCodeStartJarParOptions jarOptions,
        PkceParameters pkce,
        string state,
        string nonce,
        DateTimeOffset now) => new()
    {
        ClientId = registration.ClientId.Value,
        ResponseType = WellKnownResponseTypes.Code,
        RedirectUri = jarOptions.RedirectUri,
        Scope = jarOptions.Scope,
        State = state,
        Nonce = nonce,
        CodeChallenge = pkce.EncodedChallenge,
        CodeChallengeMethod = pkce.Method.ToString().ToUpperInvariant(),
        Iat = now,
        Nbf = now,
        Exp = now.Add(jarOptions.JarLifetime),
        Iss = registration.ClientId.Value,
        Aud = registration.AuthorizationServerIssuer.OriginalString
    };


    private static Uri BuildJarAuthorizeRedirectUri(
        Uri authorizationEndpoint,
        string clientId,
        string compactJar,
        OAuthFormEncodedFields additionalFields)
    {
        StringBuilder builder = new();
        builder.Append(authorizationEndpoint);
        builder.Append('?');
        builder.Append(OAuthRequestParameterNames.ClientId);
        builder.Append('=');
        builder.Append(Uri.EscapeDataString(clientId));
        builder.Append('&');
        builder.Append(OAuthRequestParameterNames.Request);
        builder.Append('=');
        builder.Append(Uri.EscapeDataString(compactJar));

        foreach((string key, string value) in additionalFields.Fields)
        {
            builder.Append('&');
            builder.Append(Uri.EscapeDataString(key));
            builder.Append('=');
            builder.Append(Uri.EscapeDataString(value));
        }

        return new Uri(builder.ToString());
    }


    private static PkceParameters GeneratePkceParameters(EncodeDelegate base64UrlEncoder)
    {
        return PkceGeneration.Generate(base64UrlEncoder, BaseMemoryPool.Shared);
    }

    private static OutgoingFormFields EncodeParRequestBody(ParRequestBody body)
    {
        return new OutgoingFormFields
        {
            [OAuthRequestParameterNames.ClientId] = body.ClientId,
            [OAuthRequestParameterNames.ResponseType] = body.ResponseType,
            [OAuthRequestParameterNames.RedirectUri] = body.RedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = string.Join(' ', body.Scopes),
            [OAuthRequestParameterNames.State] = body.State,
            [OAuthRequestParameterNames.CodeChallenge] = body.CodeChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = body.CodeChallengeMethod.ToString().ToUpperInvariant()
        };
    }

    private static OutgoingFormFields EncodeTokenRequest(
        string clientId,
        string code,
        Uri redirectUri,
        PkceParameters pkce)
    {
        return new OutgoingFormFields
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri.ToString(),
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier
        };
    }

    private static OutgoingFormFields EncodeRefreshRequest(string clientId, RefreshTokenRequest request)
    {
        var fields = new OutgoingFormFields
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.RefreshToken] = request.RefreshToken
        };

        if(request.Scope is not null)
        {
            fields[OAuthRequestParameterNames.Scope] = request.Scope;
        }

        return fields;
    }


    /// <summary>
    /// Attaches confidential-client authentication to <paramref name="form"/> (and, for
    /// <c>client_secret_basic</c>, to the returned <see cref="OutgoingHeaders"/>) per
    /// <see cref="ClientRegistration.AuthenticationMethod"/>: <see cref="ClientAuthenticationMethod.None"/>
    /// attaches nothing (the request relies on PKCE alone, RFC 7636);
    /// <see cref="ClientAuthenticationMethod.ClientSecretPost"/> and
    /// <see cref="ClientAuthenticationMethod.ClientSecretBasic"/> present
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>'s private-key bytes as the shared
    /// secret (RFC 6749 §2.3.1); <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> signs a
    /// <c>client_assertion</c> from the same key material via
    /// <see cref="ClientTokenEndpointAuthentication.AttachClientAssertionAsync"/> (RFC 7523 §2.2).
    /// </summary>
    private static ValueTask<OutgoingHeaders> AttachClientAuthenticationAsync(
        OutgoingFormFields form,
        ClientRegistration registration,
        Uri tokenEndpoint,
        ClientAssertionOptions? clientAssertionOptions,
        OAuthClientInfrastructure infrastructure,
        DateTimeOffset now,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        static ValueTask<OutgoingHeaders> AttachNone() =>
            ValueTask.FromResult(OutgoingHeaders.Empty);

        static ValueTask<OutgoingHeaders> AttachClientSecretPost(OutgoingFormFields form, ClientRegistration registration)
        {
            PrivateKeyMemory secret = RequireAuthenticationKey(registration);
            form.WithClientSecretPost(registration.ClientId.Value, secret.AsReadOnlySpan());

            return ValueTask.FromResult(OutgoingHeaders.Empty);
        }

        static ValueTask<OutgoingHeaders> AttachClientSecretBasic(ClientRegistration registration)
        {
            PrivateKeyMemory secret = RequireAuthenticationKey(registration);
            OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(registration.ClientId.Value, secret.AsReadOnlySpan());

            return ValueTask.FromResult(headers);
        }

        static async ValueTask<OutgoingHeaders> AttachPrivateKeyJwt(
            OutgoingFormFields form,
            ClientRegistration registration,
            Uri tokenEndpoint,
            ClientAssertionOptions? clientAssertionOptions,
            OAuthClientInfrastructure infrastructure,
            DateTimeOffset now,
            ExchangeContext context,
            CancellationToken cancellationToken)
        {
            PrivateKeyMemory signingKey = RequireAuthenticationKey(registration);
            if(clientAssertionOptions is null)
            {
                throw new InvalidOperationException(
                    "ClientAuthenticationMethod.PrivateKeyJwt requires a ClientAssertionOptions instance to sign the client_assertion.");
            }

            await ClientTokenEndpointAuthentication.AttachClientAssertionAsync(
                form,
                registration,
                tokenEndpoint,
                signingKey,
                clientAssertionOptions.SigningKeyId,
                clientAssertionOptions.HeaderSerializer,
                clientAssertionOptions.PayloadSerializer,
                clientAssertionOptions.ClientAssertionLifetime,
                infrastructure,
                now,
                context,
                cancellationToken).ConfigureAwait(false);

            return OutgoingHeaders.Empty;
        }

        return registration.AuthenticationMethod.Code switch
        {
            var c when c == ClientAuthenticationMethod.None.Code => AttachNone(),
            var c when c == ClientAuthenticationMethod.ClientSecretPost.Code => AttachClientSecretPost(form, registration),
            var c when c == ClientAuthenticationMethod.ClientSecretBasic.Code => AttachClientSecretBasic(registration),
            var c when c == ClientAuthenticationMethod.PrivateKeyJwt.Code => AttachPrivateKeyJwt(
                form, registration, tokenEndpoint, clientAssertionOptions, infrastructure, now, context, cancellationToken),
            _ => throw new NotSupportedException(
                $"Client authentication method '{ClientAuthenticationMethodNames.GetName(registration.AuthenticationMethod)}' " +
                "is not supported on the authorization-code token or refresh leg.")
        };
    }


    /// <summary>
    /// Reads the confidential-client secret or signing key from
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>, non-owning per its own remarks —
    /// the caller reads the key's bytes via <see cref="SensitiveMemory.AsReadOnlySpan"/> for the
    /// duration of the call and does not retain or copy them.
    /// </summary>
    private static PrivateKeyMemory RequireAuthenticationKey(ClientRegistration registration) =>
        registration.AuthenticationKeyMaterial?.PrivateKey
        ?? throw new InvalidOperationException(
            $"ClientAuthenticationMethod.{ClientAuthenticationMethodNames.GetName(registration.AuthenticationMethod)} " +
            "requires ClientRegistration.AuthenticationKeyMaterial to carry the client secret or signing key.");


    private static Uri BuildAuthorizationRedirectUri(
        Uri authorizationEndpoint,
        string clientId,
        Uri requestUri)
    {
        string uri = $"{authorizationEndpoint}?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(clientId)}" +
                     $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(requestUri.ToString())}";
        return new Uri(uri);
    }


    /// <summary>
    /// Resolves the authorization server's metadata via
    /// <see cref="OAuthClientInfrastructure.ResolveAuthorizationServerMetadataAsync"/> and
    /// verifies its <see cref="AuthorizationServerMetadata.Issuer"/> against the pinned
    /// <see cref="ClientRegistration.AuthorizationServerIssuer"/> via
    /// <see cref="AuthorizationServerMetadataValidation.IsIssuerMatch"/> — RFC 8414 §3.3's
    /// issuer-match requirement, which for a client relying on OAuth metadata is also RFC 9207
    /// §2.4's "clients ... MUST compare the iss parameter value to the issuer value in the
    /// server's metadata document" reduced to the metadata-consistency half (the
    /// callback-<c>iss</c> half is <see cref="ValidationChecks.CheckCallbackIssuerMatches"/>).
    /// Every flow handler resolves metadata through this one seam so the check applies
    /// uniformly rather than needing to be repeated per call site.
    /// </summary>
    private static async ValueTask<Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult>> ResolveValidatedAuthorizationServerMetadataAsync(
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        AuthorizationServerMetadata metadata = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

        if(!AuthorizationServerMetadataValidation.IsIssuerMatch(metadata, registration.AuthorizationServerIssuer))
        {
            return Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult>.Failure(
                new AuthCodeFlowEndpointResult
                {
                    Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                    ErrorCode = "invalid_request",
                    ErrorDescription =
                        "The authorization server metadata issuer does not match this registration's " +
                        "pinned AuthorizationServerIssuer (RFC 8414 §3.3 / RFC 9207 §2.4)."
                });
        }

        return Result<AuthorizationServerMetadata, AuthCodeFlowEndpointResult>.Success(metadata);
    }


    /// <summary>
    /// Builds the result for an OAuth 2.0 Authorization Error Response callback
    /// (<paramref name="errorCode"/> present per RFC 6749 §4.1.2.1). Applies the RFC 9207
    /// §2.4 / §4 mix-up defense to the error path: when <paramref name="fields"/>' <c>state</c>
    /// correlates to a pending <see cref="ParCompletedState"/> flow and the callback carries a
    /// PRESENT <c>iss</c> that does not match that flow's recorded issuer
    /// (<see cref="ValidationChecks.CheckCallbackIssuerMatchesWhenPresent"/>), the response is
    /// rejected as tampering — an attacker able to inject <c>iss</c> on a forged success
    /// response is equally able to inject <c>error</c> and <c>iss</c> together, and RFC 9207 §4
    /// draws no distinction between success and error responses for this defense. When
    /// <c>state</c> does not correlate to a pending flow, or the callback carries no <c>iss</c>,
    /// there is no expected-issuer value to validate against and the authorization server's
    /// error is returned as received.
    /// </summary>
    private static async ValueTask<AuthCodeFlowEndpointResult> BuildCallbackErrorResultAsync(
        IReadOnlyDictionary<string, string> fields,
        OAuthClientInfrastructure infrastructure,
        ExchangeContext context,
        string errorCode,
        CancellationToken cancellationToken)
    {
        fields.TryGetValue(OAuthRequestParameterNames.ErrorDescription, out string? errorDescription);

        if(fields.TryGetValue(OAuthRequestParameterNames.State, out string? errorState))
        {
            FlowState? errorFlowState = await infrastructure.LoadStateAsync(
                errorState, context, cancellationToken).ConfigureAwait(false);

            if(errorFlowState is ParCompletedState errorParCompleted)
            {
                ValidationContext issuerCheckContext = new()
                {
                    Context = new ExchangeContext(),
                    Fields = fields,
                    FlowState = errorParCompleted,
                    Now = infrastructure.TimeProvider.GetUtcNow()
                };

                List<Claim> issuerClaims = await ValidationChecks.CheckCallbackIssuerMatchesWhenPresent(
                    issuerCheckContext, cancellationToken).ConfigureAwait(false);

                if(issuerClaims.Exists(static c => c.Outcome != ClaimOutcome.Success))
                {
                    return new AuthCodeFlowEndpointResult
                    {
                        Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                        ErrorCode = "invalid_request",
                        ErrorDescription =
                            "The iss parameter on the error callback does not match the recorded issuer; " +
                            "the response is not trusted as originating from the intended authorization " +
                            "server (RFC 9207 §2.4, RFC 9700 §4.4).",
                        ValidationClaims = issuerClaims
                    };
                }
            }
        }

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
            ErrorCode = errorCode,
            ErrorDescription = errorDescription
        };
    }


    //Maps an OAuthParseError to an AuthCodeFlowEndpointResult, surfacing the
    //decision support summary as the error description so callers have actionable
    //information without needing to pattern-match the full error hierarchy.
    private static AuthCodeFlowEndpointResult BuildEndpointResultFromParseError(
        OAuthParseError error)
    {
        return error switch
        {
            OAuthProtocolError pe => new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = pe.ErrorCode,
                ErrorDescription = pe.ErrorDescription ?? pe.Support.Summary
            },
            OAuthInvalidFieldValue ifv => new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_response",
                ErrorDescription = $"{ifv.FieldName}: {ifv.Reason}"
            },
            OAuthMalformedResponse mr => new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.InternalError,
                ErrorCode = "server_error",
                ErrorDescription = mr.Support.Summary
            },
            _ => new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.InternalError,
                ErrorCode = "server_error",
                ErrorDescription = error.Support.Summary
            }
        };
    }


    /// <summary>
    /// Builds the outgoing-headers bag for a token-endpoint request,
    /// attaching a freshly-constructed DPoP proof when the infrastructure
    /// is wired for DPoP.
    /// </summary>
    /// <remarks>
    /// The client side performs single-shot proof attachment only — there
    /// is no <c>use_dpop_nonce</c> retry loop and no nonce cache. A
    /// nonce-required AS that challenges the first attempt with a 401 +
    /// <c>DPoP-Nonce</c> response header surfaces the failure to the
    /// caller; the application can read the response and retry at a
    /// higher level. Cross-call nonce caching belongs with the AS-side
    /// validation work, where the storage shape can match
    /// the existing flow-state delegate pattern.
    /// </remarks>
    /// <summary>
    /// Sends the token request with a DPoP proof attached when the
    /// infrastructure has DPoP wired, retrying once on a
    /// <c>use_dpop_nonce</c> challenge per RFC 9449 §8.1.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The retry path applies only when the AS responds with HTTP 400 +
    /// <c>error=use_dpop_nonce</c> in the body and a fresh nonce in the
    /// <c>DPoP-Nonce</c> response header. The fresh nonce is stored in the
    /// infrastructure's nonce cache and a second proof is constructed
    /// echoing it. There is no exponential backoff and no second retry —
    /// applications wanting elaborate retry policies wrap this call.
    /// </para>
    /// <para>
    /// When DPoP is not wired (proof construction or key absent), the
    /// request is sent without DPoP and the response is returned
    /// unchanged.
    /// </para>
    /// </remarks>
    private static async ValueTask<HttpResponseData> SendTokenRequestWithDpopRetryAsync(
        OAuthClientInfrastructure infrastructure,
        Uri tokenEndpoint,
        OutgoingFormFields tokenFields,
        OutgoingHeaders authenticationHeaders,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(infrastructure.ConstructDpopProofAsync is null || infrastructure.DpopKey is null)
        {
            //DPoP not wired — send with only the client-authentication headers (e.g. client_secret_basic's
            //Authorization header), or none for a method that authenticates via the form body or not at all.
            return await infrastructure.SendFormPostAsync(
                tokenEndpoint, tokenFields, authenticationHeaders, context, cancellationToken)
                .ConfigureAwait(false);
        }

        string authority = InMemoryDpopNonceCache.AuthorityFor(tokenEndpoint);

        HttpResponseData response = await SendOnceWithDpopAsync(
            infrastructure, tokenEndpoint, tokenFields, authenticationHeaders, authority, context, cancellationToken)
            .ConfigureAwait(false);

        if(response.StatusCode != 400)
        {
            return response;
        }

        //RFC 9449 §8.1: 400 + error=use_dpop_nonce in body + DPoP-Nonce header.
        string? freshNonce = response.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
        if(freshNonce is null)
        {
            return response;
        }
        if(!response.Body.Contains(OAuthErrors.UseDpopNonce, StringComparison.Ordinal))
        {
            return response;
        }

        infrastructure.StoreDpopNonce?.Invoke(authority, freshNonce);

        return await SendOnceWithDpopAsync(
            infrastructure, tokenEndpoint, tokenFields, authenticationHeaders, authority, context, cancellationToken)
            .ConfigureAwait(false);
    }


    private static async ValueTask<HttpResponseData> SendOnceWithDpopAsync(
        OAuthClientInfrastructure infrastructure,
        Uri tokenEndpoint,
        OutgoingFormFields tokenFields,
        OutgoingHeaders authenticationHeaders,
        string authority,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        string? cachedNonce = infrastructure.LookupDpopNonce?.Invoke(authority);

        string jti = await infrastructure.GenerateIdentifierAsync(
            WellKnownIdentifierPurposes.OAuthJti, null, cancellationToken)
            .ConfigureAwait(false);

        DpopProofClaims claims = new()
        {
            Htm = WellKnownHttpMethods.Post,
            Htu = tokenEndpoint.GetLeftPart(UriPartial.Path),
            Iat = infrastructure.TimeProvider.GetUtcNow(),
            Jti = jti,
            Nonce = cachedNonce
        };

        string proof = await infrastructure.ConstructDpopProofAsync!(
            claims, infrastructure.DpopKey!, cancellationToken).ConfigureAwait(false);

        OutgoingHeaders headers = authenticationHeaders.WithDpop(proof);

        return await infrastructure.SendFormPostAsync(
            tokenEndpoint, tokenFields, headers, context, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Produces a 32-character lowercase-hex string from 16 CSPRNG-sourced
    /// random bytes via <see cref="OAuthClientInfrastructure.FillEntropy"/>.
    /// Wire-format-compatible with the prior <c>Guid.NewGuid().ToString("N")</c>
    /// shape — same length, same character set, same expected entropy.
    /// </summary>
    private static string GenerateEntropyHexString(OAuthClientInfrastructure infrastructure)
    {
        Span<byte> buffer = stackalloc byte[16];
        infrastructure.FillEntropy(buffer);
        return Convert.ToHexStringLower(buffer);
    }
}
