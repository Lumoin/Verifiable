using System.Globalization;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth;

/// <summary>
/// Default parsers for OAuth 2.0 protocol endpoint responses.
/// </summary>
/// <remarks>
/// <para>
/// These parsers implement the delegate contracts defined in
/// <see cref="ParseParResponseDelegate"/> and <see cref="ParseTokenResponseDelegate"/>.
/// They take no dependency on <c>System.Text.Json</c> or any serialization infrastructure.
/// </para>
/// <para>
/// A response's parameters are the members at the top level of the one JSON object its body is: RFC 6749 §5.1 has a token
/// response's parameters serialized "into a JSON structure by adding each parameter at the highest structure level", as
/// RFC 9126 §2.2 has a pushed authorization response's. The body is read as that object
/// (<see cref="JwkJsonReader.ReadTopLevelMembers"/>), never searched as text: each name and string value decoded once
/// (RFC 8259 §7), a member an object nested beneath the top level carries never read as a parameter, and a body that is
/// not one well-formed JSON object, or that repeats a member name (RFC 8259 §4), answered as malformed. A reader of the same
/// body as the JSON it is - a client's check of the credentials it carries - therefore reads the very values these parsers
/// answer.
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
    /// <param name="response">The response.</param>
    /// <returns>The request URI and its lifetime, the error the response names, or the refusal of a malformed response.</returns>
    public static Result<ParResponse, OAuthParseError> ParseParResponse(
        HttpResponseData response)
    {
        if(response.Body.AsSpan().Trim().IsEmpty)
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

        var members = MembersOf(response.Body);

        if(response.IsProblemJson)
        {
            return ParseProblemJson<ParResponse>(members ?? [], response);
        }

        if(members is null)
        {
            return Result.Failure<ParResponse, OAuthParseError>(
                NotOneObject(response, "PAR", "RFC 9126 §2.2").WithTransportMetadata(response));
        }

        if(StringOf(members, OAuthRequestParameterNames.Error) is { } errorCode)
        {
            return BuildProtocolError<ParResponse>(errorCode, members, response,
                endpoint: "PAR",
                specReference: "RFC 9126 §2.3");
        }

        if(StringOf(members, OAuthRequestParameterNames.RequestUri) is not { } requestUriString)
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

        if(!TryIntegerOf(members, OAuthRequestParameterNames.ExpiresIn, out int expiresIn))
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
    /// <param name="response">The response.</param>
    /// <param name="receivedAt">The instant the response was received.</param>
    /// <returns>The token response, the error the response names, or the refusal of a malformed response.</returns>
    public static Result<TokenResponse, OAuthParseError> ParseTokenResponse(
        HttpResponseData response,
        DateTimeOffset receivedAt)
    {
        if(response.Body.AsSpan().Trim().IsEmpty)
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

        var members = MembersOf(response.Body);

        if(response.IsProblemJson)
        {
            return ParseProblemJson<TokenResponse>(members ?? [], response);
        }

        if(members is null)
        {
            return Result.Failure<TokenResponse, OAuthParseError>(
                NotOneObject(response, "token", "RFC 6749 §5.1").WithTransportMetadata(response));
        }

        if(StringOf(members, OAuthRequestParameterNames.Error) is { } errorCode)
        {
            return BuildProtocolError<TokenResponse>(errorCode, members, response,
                endpoint: "token",
                specReference: "RFC 6749 §5.2");
        }

        if(StringOf(members, OAuthRequestParameterNames.AccessToken) is not { Length: > 0 } accessToken)
        {
            return Result.Failure<TokenResponse, OAuthParseError>(
                new OAuthMalformedResponse(
                    response.Body,
                    new DecisionSupport("The token response did not contain an access_token.")
                    {
                        LikelyCause = "The server did not return a valid token response. " +
                                      "The response may be an error without using the " +
                                      "standard error field, or carry its parameters below " +
                                      "the highest structure level.",
                        SpecificationReference = "RFC 6749 §5.1"
                    }).WithTransportMetadata(response));
        }

        if(StringOf(members, OAuthRequestParameterNames.TokenType) is not { Length: > 0 } tokenType)
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
        if(TryIntegerOf(members, OAuthRequestParameterNames.ExpiresIn, out int expiresInValue))
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

        return Result.Success<TokenResponse, OAuthParseError>(
            new TokenResponse
            {
                AccessToken = accessToken,
                TokenType = tokenType,
                ExpiresIn = expiresIn,
                RefreshToken = StringOf(members, OAuthRequestParameterNames.RefreshToken),
                Scope = StringOf(members, OAuthRequestParameterNames.Scope),
                IdToken = StringOf(members, OAuthRequestParameterNames.IdToken),
                IssuedTokenType = StringOf(members, OAuthRequestParameterNames.IssuedTokenType)
            });
    }


    /// <summary>
    /// The parameters a response body carries: the members at the top level of the one JSON object it is, each name and
    /// string value decoded once, or <see langword="null"/> for a body that is not one well-formed JSON object.
    /// </summary>
    /// <param name="body">The response body.</param>
    /// <returns>The top-level members, or <see langword="null"/>.</returns>
    private static IReadOnlyList<JsonTopLevelMember>? MembersOf(string body) =>
        JwkJsonReader.ReadTopLevelMembers(Encoding.UTF8.GetBytes(body));


    /// <summary>
    /// The decoded string a top-level parameter carries, or <see langword="null"/> when the response carries no such parameter
    /// or carries it as no string, or as a string naming no Unicode text. A well-formed object names each member once, so the
    /// member found is the one the object carries.
    /// </summary>
    /// <param name="members">The response's top-level members.</param>
    /// <param name="name">The parameter's name.</param>
    /// <returns>The parameter's value, or <see langword="null"/>.</returns>
    private static string? StringOf(IReadOnlyList<JsonTopLevelMember> members, string name)
    {
        foreach(var member in members)
        {
            if(member.Kind is JsonTopLevelValueKind.String && string.Equals(member.Name, name, StringComparison.Ordinal))
            {
                return member.Text;
            }
        }

        return null;
    }


    /// <summary>
    /// Reads a top-level parameter carried as a JSON number naming an integer within the range of <see cref="int"/>.
    /// </summary>
    /// <param name="members">The response's top-level members.</param>
    /// <param name="name">The parameter's name.</param>
    /// <param name="value">The integer, or zero when none is read.</param>
    /// <returns><see langword="true"/> when the parameter is carried as such a number.</returns>
    private static bool TryIntegerOf(IReadOnlyList<JsonTopLevelMember> members, string name, out int value)
    {
        foreach(var member in members)
        {
            if(member.Kind is JsonTopLevelValueKind.Number && string.Equals(member.Name, name, StringComparison.Ordinal))
            {
                return int.TryParse(member.Text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);
            }
        }

        value = 0;

        return false;
    }


    /// <summary>
    /// The refusal of a response body that is not one well-formed JSON object, whose top-level members alone are a
    /// response's parameters.
    /// </summary>
    /// <param name="response">The response.</param>
    /// <param name="endpoint">The endpoint that answered it.</param>
    /// <param name="specReference">The clause the response's form is given by.</param>
    /// <returns>The refusal.</returns>
    private static OAuthMalformedResponse NotOneObject(HttpResponseData response, string endpoint, string specReference) => new(
        response.Body,
        new DecisionSupport($"The {endpoint} endpoint's response is not one well-formed JSON object.")
        {
            LikelyCause = "The body is no JSON object, is not well-formed JSON, or repeats a member name " +
                          "(RFC 8259 §4), so it names no parameter one way.",
            SpecificationReference = specReference
        });


    /// <summary>
    /// The OAuth error response a body's top-level <c>error</c> names (RFC 6749 §5.2), with the description and the URI it
    /// carries beside it.
    /// </summary>
    /// <typeparam name="T">The success type the endpoint's parser answers.</typeparam>
    /// <param name="errorCode">The <c>error</c> the response names.</param>
    /// <param name="members">The response's top-level members.</param>
    /// <param name="response">The response.</param>
    /// <param name="endpoint">The endpoint that answered it.</param>
    /// <param name="specReference">The clause the error response is given by.</param>
    /// <returns>The protocol error.</returns>
    private static Result<T, OAuthParseError> BuildProtocolError<T>(
        string errorCode,
        IReadOnlyList<JsonTopLevelMember> members,
        HttpResponseData response,
        string endpoint,
        string specReference)
    {
        string? description = StringOf(members, OAuthRequestParameterNames.ErrorDescription) is { Length: > 0 } carried ? carried : null;

        Uri? errorUri = null;
        if(StringOf(members, "error_uri") is { Length: > 0 } errorUriText)
        {
            _ = Uri.TryCreate(errorUriText, UriKind.Absolute, out errorUri);
        }

        DecisionSupport support = BuildProtocolErrorSupport(
            errorCode, description, endpoint, specReference);

        return Result.Failure<T, OAuthParseError>(
            new OAuthProtocolError(errorCode, support, description, errorUri)
                .WithTransportMetadata(response));
    }


    /// <summary>
    /// The RFC 9457 problem a <c>problem+json</c> response states, read from its top-level <c>type</c>, <c>detail</c> and
    /// <c>instance</c> members, none of them where the body is no JSON object.
    /// </summary>
    /// <typeparam name="T">The success type the endpoint's parser answers.</typeparam>
    /// <param name="members">The response's top-level members, empty where the body is no JSON object.</param>
    /// <param name="response">The response.</param>
    /// <returns>The protocol error.</returns>
    private static Result<T, OAuthParseError> ParseProblemJson<T>(
        IReadOnlyList<JsonTopLevelMember> members,
        HttpResponseData response)
    {
        string errorCode = StringOf(members, "type") is { Length: > 0 } type ? type : "problem";
        string? detail = StringOf(members, "detail") is { Length: > 0 } carriedDetail ? carriedDetail : null;
        string? instance = StringOf(members, "instance") is { Length: > 0 } carriedInstance ? carriedInstance : null;

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


    /// <summary>The decision support an OAuth error code is answered with: its likely cause and the guidance acting on it.</summary>
    /// <param name="errorCode">The error code.</param>
    /// <param name="serverDescription">The description the server wrote, or <see langword="null"/>.</param>
    /// <param name="endpoint">The endpoint that answered it.</param>
    /// <param name="specReference">The clause the error response is given by.</param>
    /// <returns>The decision support.</returns>
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
}
