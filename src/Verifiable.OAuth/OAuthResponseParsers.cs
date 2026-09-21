using System.Globalization;
using Verifiable.Core;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth;

/// <summary>
/// Default span-based parsers for OAuth 2.0 protocol endpoint responses.
/// </summary>
/// <remarks>
/// <para>
/// These parsers implement the delegate contracts defined in
/// <see cref="ParseParResponseDelegate"/> and <see cref="ParseTokenResponseDelegate"/>.
/// They use <see cref="ReadOnlySpan{T}"/> scanning with no dependency on
/// <c>System.Text.Json</c> or any serialization infrastructure.
/// </para>
/// <para>
/// Both parsers handle two response shapes:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       Standard OAuth error response per
///       <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>
///       — a JSON object with <c>error</c> and optional <c>error_description</c>,
///       <c>error_uri</c>.
///     </description>
///   </item>
///   <item>
///     <description>
///       RFC 9457 problem+json response — detected when
///       <see cref="HttpResponseData.IsProblemJson"/> is <see langword="true"/>.
///       The <c>detail</c> field maps to <c>error_description</c> and the
///       <c>instance</c> field becomes the <see cref="DecisionSupport.CorrelationId"/>.
///     </description>
///   </item>
/// </list>
/// <para>
/// <strong>Usage in <see cref="OAuthClientInfrastructure"/>:</strong>
/// </para>
/// <code>
/// OAuthClientInfrastructure.Create(
///     ...
///     parseParResponseAsync:   OAuthResponseParsers.ParseParResponse,
///     parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
///     ...);
/// </code>
/// </remarks>
public static class OAuthResponseParsers
{
    /// <summary>
    /// Parses a PAR endpoint response per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
    /// </summary>
    public static Result<ParResponse, OAuthParseError> ParseParResponse(
        HttpResponseData response)
    {
        ReadOnlySpan<char> body = response.Body.AsSpan().Trim();

        if(body.IsEmpty)
        {
            return Result.Failure<ParResponse, OAuthParseError>(
                new OAuthMalformedResponse(
                    response.Body,
                    new DecisionSupport("The PAR endpoint returned an empty response body.")
                    {
                        LikelyCause = "The endpoint URL may be incorrect, a proxy may have " +
                                      "intercepted the request, or the server has a bug.",
                        ActionableGuidance = "Verify the pushed_authorization_request_endpoint " +
                                             "value in the authorization server metadata.",
                        SpecificationReference = "RFC 9126 §2.2"
                    }).WithTransportMetadata(response));
        }

        if(response.IsProblemJson)
        {
            return ParseProblemJson<ParResponse>(body, response);
        }

        if(TryGetStringField(body, "error", out ReadOnlySpan<char> errorCode))
        {
            return BuildProtocolError<ParResponse>(errorCode, body, response,
                endpoint: "PAR",
                specReference: "RFC 9126 §2.3");
        }

        if(!TryGetStringField(body, "request_uri", out ReadOnlySpan<char> requestUriSpan))
        {
            return Result.Failure<ParResponse, OAuthParseError>(
                new OAuthMalformedResponse(
                    response.Body,
                    new DecisionSupport("The PAR response did not contain a request_uri field.")
                    {
                        LikelyCause = "The server did not conform to RFC 9126 §2.2, or the " +
                                      "response body is not a PAR success response.",
                        ActionableGuidance = "Inspect the raw response body. If the server " +
                                             "returned an error without using the standard " +
                                             "error field, check the server logs.",
                        SpecificationReference = "RFC 9126 §2.2"
                    }).WithTransportMetadata(response));
        }

        string requestUriString = requestUriSpan.ToString();
        //Absolute URI AND an acceptable scheme. UriKind.Absolute alone is not enough: on
        //Unix a leading-slash value like "/relative/path" parses as an absolute file: URI
        //(it is a valid Unix file path), so a relative request_uri would slip through there
        //while being rejected on Windows. RFC 9126 §2.2 request_uri values are https URLs or
        //the urn:ietf:params:oauth:request_uri: form; restrict to those (http for loopback).
        if(!Uri.TryCreate(requestUriString, UriKind.Absolute, out Uri? requestUri)
            || !(string.Equals(requestUri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
                || string.Equals(requestUri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
                || string.Equals(requestUri.Scheme, "urn", StringComparison.Ordinal)))
        {
            return Result.Failure<ParResponse, OAuthParseError>(
                new OAuthInvalidFieldValue(
                    "request_uri",
                    requestUriString,
                    "The request_uri value is not a valid absolute https or urn URI.",
                    new DecisionSupport("The PAR response contained an invalid request_uri value.")
                    {
                        LikelyCause = "The authorization server returned a malformed " +
                                      "request_uri. RFC 9126 §2.2 requires an absolute https " +
                                      "(or urn:ietf:params:oauth:request_uri:) URI.",
                        SpecificationReference = "RFC 9126 §2.2"
                    }).WithTransportMetadata(response));
        }

        if(!TryGetIntField(body, "expires_in", out int expiresIn))
        {
            return Result.Failure<ParResponse, OAuthParseError>(
                new OAuthMalformedResponse(
                    response.Body,
                    new DecisionSupport("The PAR response did not contain a valid expires_in field.")
                    {
                        LikelyCause = "The expires_in field is missing or not a number.",
                        SpecificationReference = "RFC 9126 §2.2"
                    }).WithTransportMetadata(response));
        }

        if(expiresIn <= 0)
        {
            return Result.Failure<ParResponse, OAuthParseError>(
                new OAuthInvalidFieldValue(
                    "expires_in",
                    expiresIn.ToString(CultureInfo.InvariantCulture),
                    "The expires_in value must be a positive integer. " +
                    "RFC 9126 §2.2 requires the request URI to have a positive lifetime.",
                    new DecisionSupport("The PAR response contained an invalid expires_in value.")
                    {
                        LikelyCause = "The authorization server returned zero or a negative " +
                                      "lifetime, which is not permitted.",
                        SpecificationReference = "RFC 9126 §2.2"
                    }).WithTransportMetadata(response));
        }

        return Result.Success<ParResponse, OAuthParseError>(new ParResponse(requestUri, expiresIn));
    }


    /// <summary>
    /// Parses a token endpoint response per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>.
    /// </summary>
    public static Result<TokenResponse, OAuthParseError> ParseTokenResponse(
        HttpResponseData response,
        DateTimeOffset receivedAt)
    {
        ReadOnlySpan<char> body = response.Body.AsSpan().Trim();

        if(body.IsEmpty)
        {
            return Result.Failure<TokenResponse, OAuthParseError>(
                new OAuthMalformedResponse(
                    response.Body,
                    new DecisionSupport("The token endpoint returned an empty response body.")
                    {
                        LikelyCause = "The endpoint URL may be incorrect or the server " +
                                      "returned a response with no body.",
                        ActionableGuidance = "Verify the token_endpoint value in the " +
                                             "authorization server metadata.",
                        SpecificationReference = "RFC 6749 §5.1"
                    }).WithTransportMetadata(response));
        }

        if(response.IsProblemJson)
        {
            return ParseProblemJson<TokenResponse>(body, response);
        }

        if(TryGetStringField(body, "error", out ReadOnlySpan<char> errorCode))
        {
            return BuildProtocolError<TokenResponse>(errorCode, body, response,
                endpoint: "token",
                specReference: "RFC 6749 §5.2");
        }

        if(!TryGetStringField(body, "access_token", out ReadOnlySpan<char> accessTokenSpan)
            || accessTokenSpan.IsEmpty)
        {
            return Result.Failure<TokenResponse, OAuthParseError>(
                new OAuthMalformedResponse(
                    response.Body,
                    new DecisionSupport("The token response did not contain an access_token.")
                    {
                        LikelyCause = "The server did not return a valid token response. " +
                                      "The response may be an error without using the " +
                                      "standard error field.",
                        SpecificationReference = "RFC 6749 §5.1"
                    }).WithTransportMetadata(response));
        }

        if(!TryGetStringField(body, "token_type", out ReadOnlySpan<char> tokenTypeSpan)
            || tokenTypeSpan.IsEmpty)
        {
            return Result.Failure<TokenResponse, OAuthParseError>(
                new OAuthMalformedResponse(
                    response.Body,
                    new DecisionSupport("The token response did not contain a token_type.")
                    {
                        LikelyCause = "The server returned an access_token without a " +
                                      "token_type, which is not permitted by RFC 6749 §5.1.",
                        SpecificationReference = "RFC 6749 §5.1"
                    }).WithTransportMetadata(response));
        }

        int? expiresIn = null;
        if(TryGetIntField(body, "expires_in", out int expiresInValue))
        {
            if(expiresInValue <= 0)
            {
                return Result.Failure<TokenResponse, OAuthParseError>(
                    new OAuthInvalidFieldValue(
                        "expires_in",
                        expiresInValue.ToString(CultureInfo.InvariantCulture),
                        "expires_in must be a positive integer.",
                        new DecisionSupport("The token response contained an invalid expires_in value.")
                        {
                            SpecificationReference = "RFC 6749 §5.1"
                        }).WithTransportMetadata(response));
            }

            expiresIn = expiresInValue;
        }

        string? refreshToken = TryGetStringField(body, "refresh_token", out ReadOnlySpan<char> rt)
            ? rt.ToString() : null;

        string? scope = TryGetStringField(body, "scope", out ReadOnlySpan<char> sc)
            ? sc.ToString() : null;

        string? idToken = TryGetStringField(body, "id_token", out ReadOnlySpan<char> idt)
            ? idt.ToString() : null;

        return Result.Success<TokenResponse, OAuthParseError>(
            new TokenResponse
            {
                AccessToken = accessTokenSpan.ToString(),
                TokenType = tokenTypeSpan.ToString(),
                ExpiresIn = expiresIn,
                RefreshToken = refreshToken,
                Scope = scope,
                IdToken = idToken
            });
    }


    /// <summary>
    /// Parses an authorization server (or OpenID Provider) metadata document per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.2">RFC 8414 §3.2</see>.
    /// </summary>
    /// <remarks>
    /// Every <see cref="Uri"/> member is read as an absolute URI; a present-but-malformed value is
    /// an <see cref="OAuthInvalidFieldValue"/> naming the member, per RFC 8414 §2's per-member
    /// "URL of the authorization server's ... endpoint" definitions. Every <c>*_supported</c> member
    /// is read as a JSON string array via <see cref="TryGetStringArrayField"/>; an absent boolean
    /// member reads as <see langword="false"/>, the unstated default RFC 8414 §2's OPTIONAL boolean
    /// members carry. A member this type does not carry is ignored per RFC 8414 §3.2: "a JSON object
    /// ... that contains a set of claims as its members that are a subset of the metadata values
    /// defined in Section 2. Other claims MAY also be returned."
    /// </remarks>
    public static Result<AuthorizationServerMetadata, OAuthParseError> ParseAuthorizationServerMetadata(
        HttpResponseData response)
    {
        ReadOnlySpan<char> body = response.Body.AsSpan().Trim();

        if(body.IsEmpty)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(
                new OAuthMalformedResponse(
                    response.Body,
                    new DecisionSupport("The authorization server metadata response was empty.")
                    {
                        LikelyCause = "The well-known metadata URL may be incorrect, a proxy may " +
                                      "have intercepted the request, or the server has a bug.",
                        SpecificationReference = "RFC 8414 §3.2"
                    }).WithTransportMetadata(response));
        }

        if(!TryGetStringField(body, AuthorizationServerMetadataParameterNames.Issuer, out ReadOnlySpan<char> issuerSpan)
            || issuerSpan.IsEmpty)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(
                new OAuthMalformedResponse(
                    response.Body,
                    new DecisionSupport("The authorization server metadata document did not contain an issuer.")
                    {
                        LikelyCause = "RFC 8414 §2 makes the issuer member REQUIRED: \"The authorization " +
                                      "server's issuer identifier, which is a URL that uses the 'https' " +
                                      "scheme and has no query or fragment components.\"",
                        SpecificationReference = "RFC 8414 §2"
                    }).WithTransportMetadata(response));
        }

        string issuerString = issuerSpan.ToString();
        if(!Uri.TryCreate(issuerString, UriKind.Absolute, out Uri? issuerUri))
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(
                new OAuthInvalidFieldValue(
                    AuthorizationServerMetadataParameterNames.Issuer,
                    issuerString,
                    "The issuer value is not an absolute URI.",
                    new DecisionSupport("The authorization server metadata document's issuer value is not a valid absolute URI.")
                    {
                        SpecificationReference = "RFC 8414 §2"
                    }).WithTransportMetadata(response));
        }

        (Uri? authorizationEndpoint, OAuthParseError? authorizationEndpointError) =
            TryParseOptionalUriField(body, AuthorizationServerMetadataParameterNames.AuthorizationEndpoint, response);
        if(authorizationEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(authorizationEndpointError);
        }

        (Uri? tokenEndpoint, OAuthParseError? tokenEndpointError) =
            TryParseOptionalUriField(body, AuthorizationServerMetadataParameterNames.TokenEndpoint, response);
        if(tokenEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(tokenEndpointError);
        }

        (Uri? pushedAuthorizationRequestEndpoint, OAuthParseError? pushedAuthorizationRequestEndpointError) =
            TryParseOptionalUriField(body, AuthorizationServerMetadataParameterNames.PushedAuthorizationRequestEndpoint, response);
        if(pushedAuthorizationRequestEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(pushedAuthorizationRequestEndpointError);
        }

        (Uri? revocationEndpoint, OAuthParseError? revocationEndpointError) =
            TryParseOptionalUriField(body, AuthorizationServerMetadataParameterNames.RevocationEndpoint, response);
        if(revocationEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(revocationEndpointError);
        }

        (Uri? introspectionEndpoint, OAuthParseError? introspectionEndpointError) =
            TryParseOptionalUriField(body, AuthorizationServerMetadataParameterNames.IntrospectionEndpoint, response);
        if(introspectionEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(introspectionEndpointError);
        }

        (Uri? jwksUri, OAuthParseError? jwksUriError) =
            TryParseOptionalUriField(body, AuthorizationServerMetadataParameterNames.JwksUri, response);
        if(jwksUriError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(jwksUriError);
        }

        (Uri? registrationEndpoint, OAuthParseError? registrationEndpointError) =
            TryParseOptionalUriField(body, AuthorizationServerMetadataParameterNames.RegistrationEndpoint, response);
        if(registrationEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(registrationEndpointError);
        }

        (Uri? endSessionEndpoint, OAuthParseError? endSessionEndpointError) =
            TryParseOptionalUriField(body, AuthorizationServerMetadataParameterNames.EndSessionEndpoint, response);
        if(endSessionEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(endSessionEndpointError);
        }

        (Uri? userInfoEndpoint, OAuthParseError? userInfoEndpointError) =
            TryParseOptionalUriField(body, OpenIdProviderMetadataParameterNames.UserinfoEndpoint, response);
        if(userInfoEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(userInfoEndpointError);
        }

        (Uri? deviceAuthorizationEndpoint, OAuthParseError? deviceAuthorizationEndpointError) =
            TryParseOptionalUriField(body, AuthorizationServerMetadataParameterNames.DeviceAuthorizationEndpoint, response);
        if(deviceAuthorizationEndpointError is not null)
        {
            return Result.Failure<AuthorizationServerMetadata, OAuthParseError>(deviceAuthorizationEndpointError);
        }

        _ = TryGetStringArrayField(body, AuthorizationServerMetadataParameterNames.ResponseTypesSupported, out List<string> responseTypesSupported);
        _ = TryGetStringArrayField(body, AuthorizationServerMetadataParameterNames.GrantTypesSupported, out List<string> grantTypesSupported);
        _ = TryGetStringArrayField(body, AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported, out List<string> tokenEndpointAuthMethodsSupported);
        _ = TryGetStringArrayField(body, AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupported, out List<string> tokenEndpointAuthSigningAlgValuesSupported);
        _ = TryGetStringArrayField(body, AuthorizationServerMetadataParameterNames.ScopesSupported, out List<string> scopesSupported);
        _ = TryGetStringArrayField(body, AuthorizationServerMetadataParameterNames.CodeChallengeMethodsSupported, out List<string> codeChallengeMethodsSupported);
        _ = TryGetStringArrayField(body, OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported, out List<string> idTokenSigningAlgValuesSupported);
        _ = TryGetStringArrayField(body, AuthorizationServerMetadataParameterNames.RequestObjectSigningAlgValuesSupported, out List<string> requestObjectSigningAlgValuesSupported);
        _ = TryGetStringArrayField(body, AuthorizationServerMetadataParameterNames.DpopSigningAlgValuesSupported, out List<string> dpopSigningAlgValuesSupported);

        _ = TryGetBooleanField(body, AuthorizationServerMetadataParameterNames.RequirePushedAuthorizationRequests, out bool requirePushedAuthorizationRequests);
        _ = TryGetBooleanField(body, AuthorizationServerMetadataParameterNames.AuthorizationResponseIssParameterSupported, out bool authorizationResponseIssParameterSupported);
        _ = TryGetBooleanField(body, AuthorizationServerMetadataParameterNames.RequireSignedRequestObject, out bool requireSignedRequestObject);
        _ = TryGetBooleanField(body, AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported, out bool clientIdMetadataDocumentSupported);

        return Result.Success<AuthorizationServerMetadata, OAuthParseError>(
            new AuthorizationServerMetadata
            {
                Issuer = issuerUri,
                AuthorizationEndpoint = authorizationEndpoint,
                TokenEndpoint = tokenEndpoint,
                PushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint,
                RevocationEndpoint = revocationEndpoint,
                IntrospectionEndpoint = introspectionEndpoint,
                JwksUri = jwksUri,
                RegistrationEndpoint = registrationEndpoint,
                EndSessionEndpoint = endSessionEndpoint,
                UserInfoEndpoint = userInfoEndpoint,
                DeviceAuthorizationEndpoint = deviceAuthorizationEndpoint,
                ResponseTypesSupported = responseTypesSupported,
                GrantTypesSupported = grantTypesSupported,
                TokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported,
                TokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported,
                ScopesSupported = scopesSupported,
                CodeChallengeMethodsSupported = codeChallengeMethodsSupported,
                IdTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported,
                RequestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported,
                DpopSigningAlgValuesSupported = dpopSigningAlgValuesSupported,
                RequirePushedAuthorizationRequests = requirePushedAuthorizationRequests,
                AuthorizationResponseIssParameterSupported = authorizationResponseIssParameterSupported,
                RequireSignedRequestObject = requireSignedRequestObject,
                ClientIdMetadataDocumentSupported = clientIdMetadataDocumentSupported
            });
    }


    /// <summary>
    /// Reads an OPTIONAL <see cref="Uri"/>-valued member of an authorization server metadata
    /// document. A member the document does not carry parses as <see langword="null"/> with no
    /// error, per RFC 8414 §2's members being OPTIONAL unless stated REQUIRED; a member present but
    /// not an absolute URI is an <see cref="OAuthInvalidFieldValue"/> naming
    /// <paramref name="memberName"/>.
    /// </summary>
    private static (Uri? Value, OAuthParseError? Error) TryParseOptionalUriField(
        ReadOnlySpan<char> body, string memberName, HttpResponseData response)
    {
        if(!TryGetStringField(body, memberName, out ReadOnlySpan<char> valueSpan))
        {
            return (null, null);
        }

        string valueString = valueSpan.ToString();
        if(Uri.TryCreate(valueString, UriKind.Absolute, out Uri? uri))
        {
            return (uri, null);
        }

        return (null, new OAuthInvalidFieldValue(
            memberName,
            valueString,
            $"The {memberName} value is not an absolute URI.",
            new DecisionSupport($"The authorization server metadata document's {memberName} value is not a valid absolute URI.")
            {
                SpecificationReference = "RFC 8414 §2"
            }).WithTransportMetadata(response));
    }


    private static Result<T, OAuthParseError> BuildProtocolError<T>(
        ReadOnlySpan<char> errorCode,
        ReadOnlySpan<char> body,
        HttpResponseData response,
        string endpoint,
        string specReference)
    {
        _ = TryGetStringField(body, "error_description", out ReadOnlySpan<char> descSpan);
        _ = TryGetStringField(body, "error_uri", out ReadOnlySpan<char> errorUriSpan);

        string errorCodeString = errorCode.ToString();
        string? description = descSpan.IsEmpty ? null : descSpan.ToString();

        Uri? errorUri = null;
        if(!errorUriSpan.IsEmpty)
        {
            _ = Uri.TryCreate(errorUriSpan.ToString(), UriKind.Absolute, out errorUri);
        }

        DecisionSupport support = BuildProtocolErrorSupport(
            errorCodeString, description, endpoint, specReference);

        return Result.Failure<T, OAuthParseError>(
            new OAuthProtocolError(errorCodeString, support, description, errorUri)
                .WithTransportMetadata(response));
    }


    private static Result<T, OAuthParseError> ParseProblemJson<T>(
        ReadOnlySpan<char> body,
        HttpResponseData response)
    {
        _ = TryGetStringField(body, "type", out ReadOnlySpan<char> typeSpan);
        _ = TryGetStringField(body, "detail", out ReadOnlySpan<char> detailSpan);
        _ = TryGetStringField(body, "instance", out ReadOnlySpan<char> instanceSpan);

        string errorCode = typeSpan.IsEmpty ? "problem" : typeSpan.ToString();
        string? detail = detailSpan.IsEmpty ? null : detailSpan.ToString();
        string? instance = instanceSpan.IsEmpty ? null : instanceSpan.ToString();

        DecisionSupport support = new(
            $"The server returned an RFC 9457 problem+json response: {errorCode}.")
        {
            LikelyCause = detail,
            SpecificationReference = "RFC 9457",
            CorrelationId = instance
        };

        return Result.Failure<T, OAuthParseError>(
            new OAuthProtocolError(errorCode, support, detail)
                .WithTransportMetadata(response));
    }


    private static DecisionSupport BuildProtocolErrorSupport(
        string errorCode,
        string? serverDescription,
        string endpoint,
        string specReference)
    {
        string summary = serverDescription is not null
            ? $"The {endpoint} endpoint returned an OAuth error: {errorCode}. Server description: {serverDescription}"
            : $"The {endpoint} endpoint returned an OAuth error: {errorCode}.";

        string? likelyCause = errorCode switch
        {
            "invalid_request" =>
                "A required parameter is missing, repeated, or malformed. " +
                "In HAIP 1.0 / FAPI 2.0 contexts this commonly means: " +
                "code_challenge is absent (PKCE downgrade), redirect_uri does not " +
                "exactly match the registered value (character-for-character), " +
                "or a required JAR parameter is missing.",
            "invalid_client" =>
                "Client authentication failed. The client_id may not be registered, " +
                "the client secret is wrong, or the client certificate does not match.",
            "unauthorized_client" =>
                "This client is not authorised to use the requested grant type or " +
                "request type. Check the client registration at the authorization server.",
            "access_denied" =>
                "The resource owner or authorization server denied the request. " +
                "The user may have cancelled, or a policy rule blocked the request.",
            "unsupported_response_type" =>
                "The authorization server does not support the requested response_type.",
            "invalid_scope" =>
                "The requested scope is invalid, unknown, malformed, or exceeds the " +
                "scope granted to the client.",
            "server_error" =>
                "The authorization server encountered an unexpected error. " +
                "This is a transient server-side problem. Retry after a delay.",
            "temporarily_unavailable" =>
                "The authorization server is temporarily unavailable. " +
                "Retry after a delay.",
            _ => null
        };

        string? guidance = errorCode switch
        {
            "invalid_request" =>
                "1. Verify the redirect_uri matches the registered value exactly. " +
                "2. Confirm code_challenge and code_challenge_method are present. " +
                "3. Check that no parameter appears more than once.",
            "invalid_client" =>
                "Verify the client_id, and if applicable the client secret or " +
                "mTLS certificate, against the authorization server registration.",
            "invalid_scope" =>
                "Check the scopes_supported field in the authorization server " +
                "metadata and ensure requested scopes are permitted for this client.",
            _ => null
        };

        return new DecisionSupport(summary)
        {
            LikelyCause = likelyCause,
            ActionableGuidance = guidance,
            SpecificationReference = specReference
        };
    }


    /// <summary>
    /// Finds <c>"key":"value"</c> in a flat JSON object and returns the value span.
    /// Handles optional whitespace around the colon and before the value string.
    /// Returns <see langword="false"/> if the key is not present or the value is
    /// not a JSON string.
    /// </summary>
    internal static bool TryGetStringField(
        ReadOnlySpan<char> json,
        string key,
        out ReadOnlySpan<char> value)
    {
        value = default;

        //Search for the quoted key — "key" — then find the colon after it,
        //skipping any whitespace between the closing quote and the colon.
        Span<char> keyPattern = stackalloc char[key.Length + 2];
        keyPattern[0] = '"';
        key.AsSpan().CopyTo(keyPattern[1..]);
        keyPattern[key.Length + 1] = '"';

        int keyIndex = json.IndexOf(keyPattern);
        if(keyIndex < 0)
        {
            return false;
        }

        ReadOnlySpan<char> afterKey = json[(keyIndex + keyPattern.Length)..].TrimStart();

        if(afterKey.IsEmpty || afterKey[0] != ':')
        {
            return false;
        }

        ReadOnlySpan<char> afterColon = afterKey[1..].TrimStart();

        if(afterColon.IsEmpty || afterColon[0] != '"')
        {
            return false;
        }

        afterColon = afterColon[1..];
        int end = FindClosingQuote(afterColon);
        if(end < 0)
        {
            return false;
        }

        value = afterColon[..end];
        return true;
    }


    /// <summary>
    /// Finds <c>"key":number</c> in a flat JSON object and returns the parsed integer.
    /// Handles optional whitespace around the colon.
    /// Returns <see langword="false"/> if the key is not present or the value is not
    /// a parseable integer.
    /// </summary>
    internal static bool TryGetIntField(
        ReadOnlySpan<char> json,
        string key,
        out int value)
    {
        value = 0;

        Span<char> keyPattern = stackalloc char[key.Length + 2];
        keyPattern[0] = '"';
        key.AsSpan().CopyTo(keyPattern[1..]);
        keyPattern[key.Length + 1] = '"';

        int keyIndex = json.IndexOf(keyPattern);
        if(keyIndex < 0)
        {
            return false;
        }

        ReadOnlySpan<char> afterKey = json[(keyIndex + keyPattern.Length)..].TrimStart();

        if(afterKey.IsEmpty || afterKey[0] != ':')
        {
            return false;
        }

        ReadOnlySpan<char> afterColon = afterKey[1..].TrimStart();
        if(afterColon.IsEmpty)
        {
            return false;
        }

        int end = 0;
        while(end < afterColon.Length
            && afterColon[end] != ','
            && afterColon[end] != '}'
            && !char.IsWhiteSpace(afterColon[end]))
        {
            ++end;
        }

        return int.TryParse(afterColon[..end], out value);
    }


    /// <summary>
    /// Finds <c>"key":[...]</c> in a flat JSON object and returns its elements as strings.
    /// Handles optional whitespace around the colon, before the opening bracket, and between
    /// elements. Returns <see langword="false"/> (with <paramref name="values"/> set to an empty
    /// list) if the key is not present, the value is not a JSON array, or an element is not a
    /// JSON string.
    /// </summary>
    internal static bool TryGetStringArrayField(
        ReadOnlySpan<char> json,
        string key,
        out List<string> values)
    {
        values = [];

        Span<char> keyPattern = stackalloc char[key.Length + 2];
        keyPattern[0] = '"';
        key.AsSpan().CopyTo(keyPattern[1..]);
        keyPattern[key.Length + 1] = '"';

        int keyIndex = json.IndexOf(keyPattern);
        if(keyIndex < 0)
        {
            return false;
        }

        ReadOnlySpan<char> afterKey = json[(keyIndex + keyPattern.Length)..].TrimStart();
        if(afterKey.IsEmpty || afterKey[0] != ':')
        {
            return false;
        }

        ReadOnlySpan<char> afterColon = afterKey[1..].TrimStart();
        if(afterColon.IsEmpty || afterColon[0] != '[')
        {
            return false;
        }

        ReadOnlySpan<char> cursor = afterColon[1..].TrimStart();
        if(!cursor.IsEmpty && cursor[0] == ']')
        {
            return true;
        }

        while(true)
        {
            if(cursor.IsEmpty || cursor[0] != '"')
            {
                values = [];

                return false;
            }

            cursor = cursor[1..];
            int end = FindClosingQuote(cursor);
            if(end < 0)
            {
                values = [];

                return false;
            }

            values.Add(cursor[..end].ToString());
            cursor = cursor[(end + 1)..].TrimStart();

            if(!cursor.IsEmpty && cursor[0] == ',')
            {
                cursor = cursor[1..].TrimStart();

                continue;
            }

            if(!cursor.IsEmpty && cursor[0] == ']')
            {
                return true;
            }

            values = [];

            return false;
        }
    }


    /// <summary>
    /// Finds <c>"key":true|false</c> in a flat JSON object and returns the parsed boolean.
    /// Handles optional whitespace around the colon. Returns <see langword="false"/> (with
    /// <paramref name="value"/> set to <see langword="false"/>) if the key is not present or the
    /// value is not a JSON boolean literal.
    /// </summary>
    internal static bool TryGetBooleanField(
        ReadOnlySpan<char> json,
        string key,
        out bool value)
    {
        value = false;

        Span<char> keyPattern = stackalloc char[key.Length + 2];
        keyPattern[0] = '"';
        key.AsSpan().CopyTo(keyPattern[1..]);
        keyPattern[key.Length + 1] = '"';

        int keyIndex = json.IndexOf(keyPattern);
        if(keyIndex < 0)
        {
            return false;
        }

        ReadOnlySpan<char> afterKey = json[(keyIndex + keyPattern.Length)..].TrimStart();
        if(afterKey.IsEmpty || afterKey[0] != ':')
        {
            return false;
        }

        ReadOnlySpan<char> afterColon = afterKey[1..].TrimStart();

        if(afterColon.StartsWith("true", StringComparison.Ordinal))
        {
            value = true;

            return true;
        }

        if(afterColon.StartsWith("false", StringComparison.Ordinal))
        {
            value = false;

            return true;
        }

        return false;
    }


    private static int FindClosingQuote(ReadOnlySpan<char> span)
    {
        for(int i = 0; i < span.Length; ++i)
        {
            if(span[i] == '\\' && i + 1 < span.Length)
            {
                ++i;
                continue;
            }

            if(span[i] == '"')
            {
                return i;
            }
        }

        return -1;
    }
}
