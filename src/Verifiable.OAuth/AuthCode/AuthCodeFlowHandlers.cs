using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Par;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Pure static handler functions for the OAuth 2.0 Authorization Code flow.
/// </summary>
/// <remarks>
/// <para>
/// Each handler takes the inbound request fields, the configured delegate bundle,
/// and a cancellation token. No instance state is held. The application author
/// wires these to HTTP routes and supplies the <see cref="AuthCodeFlowOptions"/>
/// constructed at startup.
/// </para>
/// <para>
/// Typical ASP.NET wiring (application code, not part of this library):
/// </para>
/// <code>
/// var options = new AuthCodeFlowOptions { ... };
/// var group = app.MapGroup("/oauth");
/// group.MapPost(AuthCodeFlowRoutes.Par,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleParAsync(fields, options, ct));
/// group.MapGet(AuthCodeFlowRoutes.Callback,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleCallbackAsync(fields, options, ct));
/// group.MapPost(AuthCodeFlowRoutes.Token,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleTokenAsync(fields, options, ct));
/// group.MapPost(AuthCodeFlowRoutes.Revocation,
///     (IReadOnlyDictionary&lt;string, string&gt; fields, CancellationToken ct) =>
///         AuthCodeFlowHandlers.HandleRevocationAsync(fields, options, ct));
/// </code>
/// <para>
/// In-memory state store for development and testing:
/// </para>
/// <code>
/// var store = new Dictionary&lt;string, OAuthFlowState&gt;();
/// var options = new AuthCodeFlowOptions
/// {
///     SaveStateAsync = (state, _) => { store[state.FlowId] = state; return ValueTask.CompletedTask; },
///     LoadStateAsync = (id, _)    => ValueTask.FromResult(store.GetValueOrDefault(id)),
///     ...
/// };
/// </code>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "Ownership of disposable state records is transferred to SaveStateAsync on success. " +
                    "The nullable-with-finally pattern ensures disposal on all failure paths.")]
public static class AuthCodeFlowHandlers
{
    /// <summary>
    /// Handles a pushed authorization request. Generates PKCE parameters, POSTs to
    /// the PAR endpoint, persists <see cref="ParCompleted"/> state, and returns a
    /// redirect URI for the caller to forward to the user agent.
    /// </summary>
    /// <param name="fields">
    /// Inbound form fields. May include <c>scope</c>; other required values are
    /// taken from <paramref name="options"/>.
    /// </param>
    /// <param name="options">The delegate bundle and configuration for this flow.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see cref="AuthCodeFlowEndpointOutcome.Redirect"/> on success with
    /// <see cref="AuthCodeFlowEndpointResult.RedirectUri"/> set to the authorization
    /// endpoint URI including the PAR <c>request_uri</c>.
    /// </returns>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleParAsync(
        IReadOnlyDictionary<string, string> fields,
        AuthCodeFlowOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(options);

        DateTimeOffset now = options.TimeProvider.GetUtcNow();
        string state = Guid.NewGuid().ToString("N");

        PkceParameters pkce = GeneratePkceParameters(options.Base64UrlEncoder);

        ImmutableArray<string> scopes = fields.TryGetValue(OAuthRequestParameters.Scope, out string? scopeValue)
            ? [.. scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries)]
            : ["openid"];

        var parBody = new ParRequestBody
        {
            ClientId = options.ClientId,
            CodeChallenge = pkce.EncodedChallenge,
            CodeChallengeMethod = pkce.Method,
            RedirectUri = options.RedirectUri,
            Scopes = scopes,
            State = state
        };

        Dictionary<string, string> formFields = EncodeParRequestBody(parBody);

        HttpResponseData parHttpResponse;
        try
        {
            parHttpResponse = await options.SendFormPostAsync(
                options.Endpoints.PushedAuthorizationRequestEndpoint,
                formFields,
                cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex)
        {
            pkce.Dispose();
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.InternalError,
                ErrorCode = "server_error",
                ErrorDescription = ex.Message
            };
        }

        Result<ParResponse, OAuthParseError> parResult =
            options.ParseParResponseAsync(parHttpResponse);

        if(!parResult.IsSuccess)
        {
            pkce.Dispose();
            return BuildEndpointResultFromParseError(parResult.Error!);
        }

        ParResponse parResponse = parResult.Value;
        ParCompleted? parCompleted = new ParCompleted
        {
            FlowId = state,
            ExpectedIssuer = options.Endpoints.Issuer,
            EnteredAt = now,
            ExpiresAt = now.AddSeconds(parResponse.ExpiresIn),
            Pkce = pkce,
            RedirectUri = options.RedirectUri,
            Scopes = scopes,
            Par = parResponse
        };

        try
        {
            await options.SaveStateAsync(parCompleted, cancellationToken).ConfigureAwait(false);

            Uri authorizationUri = BuildAuthorizationRedirectUri(
                options.Endpoints.AuthorizationEndpoint,
                options.ClientId,
                parResponse.RequestUri);

            parCompleted = null;

            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.Redirect,
                RedirectUri = authorizationUri
            };
        }
        finally
        {
            parCompleted?.Dispose();
        }
    }


    /// <summary>
    /// Handles the authorization server callback. Loads the flow state by the
    /// <c>state</c> parameter, runs the profile-specific validation rules, and
    /// persists <see cref="AuthorizationCodeReceived"/> state ready for token exchange.
    /// </summary>
    /// <param name="fields">
    /// The callback query parameters. Must include <c>code</c> and <c>state</c>.
    /// HAIP 1.0 additionally requires <c>iss</c>.
    /// </param>
    /// <param name="options">The delegate bundle and configuration for this flow.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleCallbackAsync(
        IReadOnlyDictionary<string, string> fields,
        AuthCodeFlowOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(options);

        if(!fields.TryGetValue(OAuthRequestParameters.Code, out string? code) ||
           !fields.TryGetValue(OAuthRequestParameters.State, out string? state))
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "Missing required callback parameters."
            };
        }

        OAuthFlowState? loaded = await options.LoadStateAsync(
            state, cancellationToken).ConfigureAwait(false);

        if(loaded is not ParCompleted parCompleted)
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "No active flow found for the supplied state value."
            };
        }

        List<Claim> validationClaims = options.ValidateCallback(
            fields, parCompleted, options.TimeProvider, cancellationToken);

        if(validationClaims.Exists(static c => c.Outcome != ClaimOutcome.Success))
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "Callback validation failed.",
                ValidationClaims = validationClaims
            };
        }

        string? iss = fields.TryGetValue(OAuthRequestParameters.Iss, out string? issValue)
            ? issValue
            : null;

        DateTimeOffset now = options.TimeProvider.GetUtcNow();

        AuthorizationCodeReceived? codeReceived = new AuthorizationCodeReceived
        {
            FlowId = parCompleted.FlowId,
            ExpectedIssuer = parCompleted.ExpectedIssuer,
            EnteredAt = now,
            ExpiresAt = parCompleted.ExpiresAt,
            Code = code,
            State = state,
            IssuerId = iss,
            Pkce = parCompleted.Pkce,
            RedirectUri = parCompleted.RedirectUri
        };

        try
        {
            await options.SaveStateAsync(codeReceived, cancellationToken).ConfigureAwait(false);

            string savedFlowId = codeReceived.FlowId;
            codeReceived = null;

            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.Ok,
                Body = new Dictionary<string, object> { [AuthCodeFlowRoutes.FlowIdField] = savedFlowId }
            };
        }
        finally
        {
            codeReceived?.Dispose();
        }
    }


    /// <summary>
    /// Handles a token exchange request. Loads the <see cref="AuthorizationCodeReceived"/>
    /// state by <c>flow_id</c>, POSTs to the token endpoint with the code and PKCE
    /// verifier, and persists <see cref="TokenReceived"/> state.
    /// </summary>
    /// <param name="fields">
    /// Inbound form fields. Must include <c>flow_id</c> to locate the pending state.
    /// </param>
    /// <param name="options">The delegate bundle and configuration for this flow.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleTokenAsync(
        IReadOnlyDictionary<string, string> fields,
        AuthCodeFlowOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(options);

        if(!fields.TryGetValue(AuthCodeFlowRoutes.FlowIdField, out string? flowId))
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "Missing required parameter: flow_id."
            };
        }

        OAuthFlowState? loaded = await options.LoadStateAsync(
            flowId, cancellationToken).ConfigureAwait(false);

        if(loaded is not AuthorizationCodeReceived codeState)
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "No code pending token exchange for the supplied flow_id."
            };
        }

        DateTimeOffset now = options.TimeProvider.GetUtcNow();
        if(now > codeState.ExpiresAt)
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "invalid_request",
                ErrorDescription = "Flow has expired."
            };
        }

        Dictionary<string, string> tokenFields = EncodeTokenRequest(
            options.ClientId,
            codeState.Code,
            codeState.RedirectUri,
            codeState.Pkce);

        HttpResponseData tokenHttpResponse = await options.SendFormPostAsync(
            options.Endpoints.TokenEndpoint,
            tokenFields,
            cancellationToken).ConfigureAwait(false);

        Result<TokenResponse, OAuthParseError> tokenResult =
            options.ParseTokenResponseAsync(tokenHttpResponse, now);

        if(!tokenResult.IsSuccess)
        {
            return BuildEndpointResultFromParseError(tokenResult.Error!);
        }

        TokenResponse tokenResponse = tokenResult.Value;
        var tokenReceived = new TokenReceived
        {
            FlowId = codeState.FlowId,
            ExpectedIssuer = codeState.ExpectedIssuer,
            EnteredAt = now,
            ExpiresAt = codeState.ExpiresAt,
            AccessToken = tokenResponse.AccessToken,
            TokenType = tokenResponse.TokenType,
            ExpiresIn = tokenResponse.ExpiresIn,
            RefreshToken = tokenResponse.RefreshToken,
            Scope = tokenResponse.Scope,
            ReceivedAt = now
        };

        await options.SaveStateAsync(tokenReceived, cancellationToken).ConfigureAwait(false);

        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.Ok,
            Body = new Dictionary<string, object>
            {
                [OAuthRequestParameters.AccessToken] = tokenResponse.AccessToken,
                [OAuthRequestParameters.TokenType] = tokenResponse.TokenType,
                [OAuthRequestParameters.ExpiresIn] = tokenResponse.ExpiresIn ?? 0,
                [OAuthRequestParameters.Scope] = tokenResponse.Scope ?? string.Empty
            }
        };
    }


    /// <summary>
    /// Handles a token revocation request. POSTs to the revocation endpoint per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009">RFC 7009</see>.
    /// </summary>
    /// <param name="fields">
    /// Inbound form fields. Must include <c>token</c>; optionally <c>token_type_hint</c>.
    /// </param>
    /// <param name="options">The delegate bundle and configuration for this flow.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> HandleRevocationAsync(
        IReadOnlyDictionary<string, string> fields,
        AuthCodeFlowOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(options);

        if(options.Endpoints.RevocationEndpoint is null)
        {
            return new AuthCodeFlowEndpointResult
            {
                Outcome = AuthCodeFlowEndpointOutcome.BadRequest,
                ErrorCode = "unsupported_token_type",
                ErrorDescription = "This authorization server does not support token revocation."
            };
        }

        if(!fields.TryGetValue(OAuthRequestParameters.Token, out string? token))
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
            [OAuthRequestParameters.ClientId] = options.ClientId,
            [OAuthRequestParameters.Token] = token
        };

        if(fields.TryGetValue(OAuthRequestParameters.TokenTypeHint, out string? hint))
        {
            revocationFields[OAuthRequestParameters.TokenTypeHint] = hint;
        }

        //RFC 7009 §2.2 — the revocation endpoint returns 200 with an empty body on
        //success. The response body is not parsed; transport errors are surfaced via
        //exception from the delegate.
        _ = await options.SendFormPostAsync(
            options.Endpoints.RevocationEndpoint,
            revocationFields,
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
    /// <param name="options">The delegate bundle and configuration for this flow.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<AuthCodeFlowEndpointResult> RefreshAsync(
        RefreshTokenRequest request,
        AuthCodeFlowOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);

        var fields = new Dictionary<string, string>
        {
            [OAuthRequestParameters.GrantType] = OAuthRequestParameters.GrantTypeRefreshToken,
            [OAuthRequestParameters.ClientId] = options.ClientId,
            [OAuthRequestParameters.RefreshToken] = request.RefreshToken
        };

        if(request.Scope is not null)
        {
            fields[OAuthRequestParameters.Scope] = request.Scope;
        }

        HttpResponseData refreshHttpResponse = await options.SendFormPostAsync(
            options.Endpoints.TokenEndpoint,
            fields,
            cancellationToken).ConfigureAwait(false);

        DateTimeOffset now = options.TimeProvider.GetUtcNow();
        Result<TokenResponse, OAuthParseError> refreshResult =
            options.ParseTokenResponseAsync(refreshHttpResponse, now);

        if(!refreshResult.IsSuccess)
        {
            return BuildEndpointResultFromParseError(refreshResult.Error!);
        }

        TokenResponse tokenResponse = refreshResult.Value;
        return new AuthCodeFlowEndpointResult
        {
            Outcome = AuthCodeFlowEndpointOutcome.Ok,
            Body = new Dictionary<string, object>
            {
                [OAuthRequestParameters.AccessToken] = tokenResponse.AccessToken,
                [OAuthRequestParameters.TokenType] = tokenResponse.TokenType,
                [OAuthRequestParameters.ExpiresIn] = tokenResponse.ExpiresIn ?? 0,
                [OAuthRequestParameters.RefreshToken] = tokenResponse.RefreshToken ?? string.Empty,
                [OAuthRequestParameters.Scope] = tokenResponse.Scope ?? string.Empty
            }
        };
    }


    private static PkceParameters GeneratePkceParameters(EncodeDelegate base64UrlEncoder)
    {
        return PkceParameters.Generate(base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);
    }

    private static Dictionary<string, string> EncodeParRequestBody(ParRequestBody body)
    {
        return new Dictionary<string, string>
        {
            [OAuthRequestParameters.ClientId] = body.ClientId,
            [OAuthRequestParameters.ResponseType] = body.ResponseType,
            [OAuthRequestParameters.RedirectUri] = body.RedirectUri.ToString(),
            [OAuthRequestParameters.Scope] = string.Join(' ', body.Scopes),
            [OAuthRequestParameters.State] = body.State,
            [OAuthRequestParameters.CodeChallenge] = body.CodeChallenge,
            [OAuthRequestParameters.CodeChallengeMethod] = body.CodeChallengeMethod.ToString().ToUpperInvariant()
        };
    }

    private static Dictionary<string, string> EncodeTokenRequest(
        string clientId,
        string code,
        Uri redirectUri,
        PkceParameters pkce)
    {
        return new Dictionary<string, string>
        {
            [OAuthRequestParameters.GrantType] = OAuthRequestParameters.GrantTypeAuthorizationCode,
            [OAuthRequestParameters.ClientId] = clientId,
            [OAuthRequestParameters.Code] = code,
            [OAuthRequestParameters.RedirectUri] = redirectUri.ToString(),
            [OAuthRequestParameters.CodeVerifier] = pkce.EncodedVerifier
        };
    }

    private static Uri BuildAuthorizationRedirectUri(
        Uri authorizationEndpoint,
        string clientId,
        Uri requestUri)
    {
        string uri = $"{authorizationEndpoint}?{OAuthRequestParameters.ClientId}={Uri.EscapeDataString(clientId)}" +
                     $"&{OAuthRequestParameters.RequestUri}={Uri.EscapeDataString(requestUri.ToString())}";
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
}