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
/// var store = new Dictionary&lt;string, OAuthFlowState&gt;();
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

        AuthorizationServerMetadata metadata = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

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

        AuthorizationServerMetadata metadata = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

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

        OAuthFlowState? loaded = await infrastructure.LoadStateAsync(
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


    /// <summary>
    /// Handles a token exchange request. Loads the <see cref="AuthorizationCodeReceivedState"/>
    /// state by <c>flow_id</c>, POSTs to the token endpoint with the code and PKCE
    /// verifier, and persists <see cref="TokenReceivedState"/> state.
    /// </summary>
    /// <param name="fields">
    /// Inbound form fields. Must include <c>flow_id</c> to locate the pending state.
    /// </param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleTokenAsync(
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

        AuthorizationServerMetadata metadata = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

        if(!fields.TryGetValue(AuthCodeFlowRoutes.FlowIdField, out string? flowId))
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "Missing required parameter: flow_id."
            };
        }

        OAuthFlowState? loaded = await infrastructure.LoadStateAsync(
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

        HttpResponseData tokenHttpResponse = await SendTokenRequestWithDpopRetryAsync(
            infrastructure, metadata.TokenEndpoint!, tokenFields, context, cancellationToken)
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

        AuthorizationServerMetadata metadata = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

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


    /// <summary>
    /// Refreshes an access token using a refresh token. Independent of the state
    /// machine — call this when the stored access token has expired.
    /// </summary>
    /// <param name="request">The refresh request parameters.</param>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the authorization server this call targets.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        RefreshTokenRequest request,
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        AuthorizationServerMetadata metadata = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

        var fields = new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeRefreshToken,
            [OAuthRequestParameterNames.ClientId] = registration.ClientId.Value,
            [OAuthRequestParameterNames.RefreshToken] = request.RefreshToken
        };

        if(request.Scope is not null)
        {
            fields[OAuthRequestParameterNames.Scope] = request.Scope;
        }

        HttpResponseData refreshHttpResponse = await infrastructure.SendFormPostAsync(
            metadata.TokenEndpoint!,
            fields,
            OutgoingHeaders.Empty,
            context,
            cancellationToken).ConfigureAwait(false);

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
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

        AuthorizationServerMetadata metadata = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

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

        AuthorizationServerMetadata metadata = await infrastructure
            .ResolveAuthorizationServerMetadataAsync(registration.AuthorizationServerIssuer, context, cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        string state = GenerateEntropyHexString(infrastructure);
        string nonce = jarOptions.Nonce ?? GenerateEntropyHexString(infrastructure);
        PkceParameters pkce = GeneratePkceParameters(infrastructure.Base64UrlEncoder);

        AuthCodeRequestObject requestObject = new()
        {
            ClientId = registration.ClientId.Value,
            ResponseType = OAuthRequestParameterValues.ResponseTypeCode,
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
        ResponseType = OAuthRequestParameterValues.ResponseTypeCode,
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
        return PkceGeneration.Generate(base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);
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
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeAuthorizationCode,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri.ToString(),
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier
        };
    }

    private static Uri BuildAuthorizationRedirectUri(
        Uri authorizationEndpoint,
        string clientId,
        Uri requestUri)
    {
        string uri = $"{authorizationEndpoint}?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(clientId)}" +
                     $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(requestUri.ToString())}";
        return new Uri(uri);
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
    /// Phase 6 client-side ships single-shot proof attachment only — there
    /// is no <c>use_dpop_nonce</c> retry loop and no nonce cache. A
    /// nonce-required AS that challenges the first attempt with a 401 +
    /// <c>DPoP-Nonce</c> response header surfaces the failure to the
    /// caller; the application can read the response and retry at a
    /// higher level. Cross-call nonce caching belongs with the AS-side
    /// validation work in phase 6b, where the storage shape can match
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
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(infrastructure.ConstructDpopProofAsync is null || infrastructure.DpopKey is null)
        {
            //DPoP not wired — send without DPoP, headers empty.
            return await infrastructure.SendFormPostAsync(
                tokenEndpoint, tokenFields, OutgoingHeaders.Empty, context, cancellationToken)
                .ConfigureAwait(false);
        }

        string authority = InMemoryDpopNonceCache.AuthorityFor(tokenEndpoint);

        HttpResponseData response = await SendOnceWithDpopAsync(
            infrastructure, tokenEndpoint, tokenFields, authority, context, cancellationToken)
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
            infrastructure, tokenEndpoint, tokenFields, authority, context, cancellationToken)
            .ConfigureAwait(false);
    }


    private static async ValueTask<HttpResponseData> SendOnceWithDpopAsync(
        OAuthClientInfrastructure infrastructure,
        Uri tokenEndpoint,
        OutgoingFormFields tokenFields,
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

        OutgoingHeaders headers = OutgoingHeaders.Empty.WithDpop(proof);

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
