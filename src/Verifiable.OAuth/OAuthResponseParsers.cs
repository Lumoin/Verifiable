using System.Buffers;
using System.Collections.Frozen;
using System.Globalization;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Oid4Vci;

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
            return BuildProtocolError<ParResponse>(
                errorCode.ToString(),
                TryGetStringField(body, "error_description", out ReadOnlySpan<char> descriptionSpan) ? descriptionSpan.ToString() : null,
                TryGetStringField(body, "error_uri", out ReadOnlySpan<char> errorUriSpan) ? errorUriSpan.ToString() : null,
                response,
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
    /// <remarks>
    /// <para>
    /// For every grant this parser serves, a body that is not an RFC 9457 problem is read as one JSON
    /// document: a body longer than <see cref="JwkJsonReader.MaximumDocumentLength"/>, counted in chars
    /// and then in UTF-8 bytes, is refused before any buffer is rented; the body is then converted to
    /// UTF-8 once, and a body is refused before any member is read when it is not well-formed JSON
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>), when it
    /// repeats a member name in any object
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see>), or when
    /// a string holds a code point the reader refuses: an unpaired surrogate or a noncharacter, escaped or
    /// not (<see href="https://www.rfc-editor.org/rfc/rfc7493#section-2.1">RFC 7493 Section 2.1</see>), or
    /// an escaped U+0000, which is this library's own rule under
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-9">RFC 8259 Section 9</see>. Both
    /// refusals are an
    /// <see cref="OAuthMalformedResponse"/>. Every member is then read by
    /// <see cref="ReadTokenResponse"/> from that copy, and only at the top level of the response
    /// object, so a member of the same name inside a nested object is never read in its place.
    /// </para>
    /// <para>
    /// Each member read is held to its grammar as <see cref="ReadTokenResponse"/> lists; among those
    /// rules, an empty <c>error</c> makes the response an <see cref="OAuthMalformedResponse"/>, an
    /// <c>error_uri</c> is surfaced in <see cref="OAuthProtocolError.ErrorUri"/> only when it is a
    /// URI-reference that is an <c>https</c> or <c>http</c> URI without userinfo, and a present
    /// <c>id_token</c> is held to the JWS Compact Serialization's base64url chars and periods.
    /// </para>
    /// <para>
    /// A success response's <c>authorization_details</c> member is read into
    /// <see cref="TokenResponse.GrantedCredentialAuthorizations"/>; a malformed member fails the parse
    /// as an <see cref="OAuthInvalidFieldValue"/> naming <c>authorization_details</c>, so no token is
    /// surfaced. A refusal past the problem+json branch carries the body as its
    /// <see cref="OAuthMalformedResponse.Body"/> only when the body is an HTML or XML document
    /// (<see cref="IsHtmlOrXmlDocument"/>: with a leading byte order mark and white space stripped, its
    /// first char is <c>&lt;</c>); every other refused body, JSON, form-encoded, plain text or anything
    /// else, carries <see cref="string.Empty"/>. An <see cref="OAuthInvalidFieldValue"/> carries
    /// <see cref="string.Empty"/> as its <see cref="OAuthInvalidFieldValue.ReceivedValue"/> unless the
    /// value is a number. The summary and reason of each refusal name it. An HTML or XML document is
    /// carried whole, whatever it holds.
    /// </para>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>:
    /// "The parameters are serialized into a JavaScript Object Notation (JSON) structure by adding each
    /// parameter at the highest structure level."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see>:
    /// "When the names within an object are not unique, the behavior of software that receives such
    /// an object is unpredictable."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-9">RFC 8259 Section 9</see>:
    /// "An implementation may set limits on the size of texts that it accepts."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-7">RFC 9396 Section 7</see>:
    /// "In addition to the token response parameters as defined in [RFC6749], the AS MUST also return
    /// the authorization_details as granted by the resource owner and assigned to the respective
    /// access token."
    /// </para>
    /// </remarks>
    /// <param name="response">The full HTTP response from the token endpoint.</param>
    /// <param name="receivedAt">The UTC instant at which the response was received.</param>
    /// <returns>The parsed Token Response, or the parse error.</returns>
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

        //A refusal from here on carries the body only when it is an HTML or XML document; every other
        //body is carried as empty.
        string diagnosticBody = IsHtmlOrXmlDocument(body) ? response.Body : string.Empty;

        //RFC 8259 Section 9: a body over the document limit is refused before any buffer is rented. A
        //char count is never more than its UTF-8 byte count, so the char count is tested first.
        if(body.Length > JwkJsonReader.MaximumDocumentLength)
        {
            return RefuseOverLongTokenResponse(diagnosticBody, response);
        }

        int byteCount = Encoding.UTF8.GetByteCount(body);
        if(byteCount > JwkJsonReader.MaximumDocumentLength)
        {
            return RefuseOverLongTokenResponse(diagnosticBody, response);
        }

        //The delegate carries no pool, so the copy is rented from the shared pool and cleared on its
        //return, since it holds the access token.
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(byteCount, 1));
        try
        {
            ReadOnlySpan<byte> tokenJson = rented.AsSpan(0, Encoding.UTF8.GetBytes(body, rented));

            return ReadTokenResponse(tokenJson, diagnosticBody, response);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }


    /// <summary>
    /// Parses a token introspection endpoint's answer per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.3">Section 2.3</see> into a
    /// <see cref="TokenIntrospectionResult"/>: the answer of a protected resource's introspection request, or the
    /// authorization server's error.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An empty body is an <see cref="OAuthMalformedResponse"/>. An RFC 9457 problem answer, named by the
    /// <c>transport.content_type</c> metadata (<see cref="HttpResponseData.IsProblemJson"/>) or by the received
    /// <c>Content-Type</c> field (<see cref="WellKnownMediaTypes.Application.IsProblemJson"/>), is read as the
    /// problem. Any other body is read as one JSON document, as the token response is read: a body longer than
    /// <see cref="JwkJsonReader.MaximumDocumentLength"/>, counted in chars and then in UTF-8 bytes, is refused before
    /// any buffer is rented; the body is then copied to UTF-8 once into a buffer rented from
    /// <paramref name="memoryPool"/>, the caller's pool, which is cleared before it is returned, since the answer may
    /// carry a credential's metadata; and a body that is not well-formed JSON
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>), repeats a member name
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see>), holds a string the
    /// reader refuses (<see href="https://www.rfc-editor.org/rfc/rfc7493#section-2.1">RFC 7493 Section 2.1</see>, and
    /// an escaped U+0000, this library's own rule under
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-9">RFC 8259 Section 9</see>) or is no object is an
    /// <see cref="OAuthMalformedResponse"/>. An object carrying an <c>error</c> member is the authorization server's
    /// error, read as the token endpoint's error is read
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>), an
    /// <see cref="OAuthProtocolError"/>; an answer of a status other than 200 without one is an
    /// <see cref="OAuthMalformedResponse"/>; a 200 answer is read by <see cref="ReadTokenIntrospectionMembers"/>.
    /// A refusal carries the body only when it is an HTML or XML document; every other refused body carries
    /// <see cref="string.Empty"/>.
    /// </para>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "The server responds
    /// with a JSON object [RFC7159] in "application/json" format with the following top-level members."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.3">Section 2.3</see>: "If the protected resource uses
    /// OAuth 2.0 client credentials to authenticate to the introspection endpoint and its credentials are invalid, the
    /// authorization server responds with an HTTP 401 (Unauthorized) as described in Section 5.2 of OAuth 2.0
    /// [RFC6749]." and "Note that a properly formed and authorized query for an inactive or otherwise invalid token (or
    /// a token the protected resource is not allowed to know about) is not considered an error response by this
    /// specification. In these cases, the authorization server MUST instead respond with an introspection response with
    /// the "active" field set to "false" as described in Section 2.2."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7493#section-2">RFC 7493 Section 2</see>: "An I-JSON message is a
    /// JSON text, as defined by RFC 7159."
    /// </para>
    /// </remarks>
    /// <param name="response">The full HTTP response from the introspection endpoint.</param>
    /// <param name="memoryPool">The pool the body's UTF-8 copy is rented from.</param>
    /// <returns>The introspection result, or the parse error.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="memoryPool"/> is <see langword="null"/>.</exception>
    public static Result<TokenIntrospectionResult, OAuthParseError> ParseTokenIntrospectionResponse(
        HttpResponseData response,
        BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);

        ReadOnlySpan<char> body = response.Body.AsSpan().Trim();
        if(body.IsEmpty)
        {
            return Result.Failure<TokenIntrospectionResult, OAuthParseError>(
                new OAuthMalformedResponse(
                    response.Body,
                    new DecisionSupport("The introspection endpoint returned an empty response body.")
                    {
                        LikelyCause = "The endpoint URL may be incorrect or the server returned a response with no body.",
                        ActionableGuidance = "Verify the introspection_endpoint value in the authorization server metadata.",
                        SpecificationReference = "RFC 7662 Section 2.2"
                    }).WithTransportMetadata(response));
        }

        if(IsProblemJsonAnswer(response))
        {
            return ParseProblemJson<TokenIntrospectionResult>(body, response);
        }

        string diagnosticBody = IsHtmlOrXmlDocument(body) ? response.Body : string.Empty;

        //RFC 8259 Section 9: a body over the document limit is refused before any buffer is rented. A char count is
        //never more than its UTF-8 byte count, so the char count is tested first.
        if(body.Length > JwkJsonReader.MaximumDocumentLength)
        {
            return RefuseOverLongIntrospectionResponse(diagnosticBody, response);
        }

        int byteCount = Encoding.UTF8.GetByteCount(body);
        if(byteCount > JwkJsonReader.MaximumDocumentLength)
        {
            return RefuseOverLongIntrospectionResponse(diagnosticBody, response);
        }

        using IMemoryOwner<byte> copyOwner = memoryPool.Rent(Math.Max(byteCount, 1));
        Span<byte> copy = copyOwner.Memory.Span;
        try
        {
            int written = Encoding.UTF8.GetBytes(body, copy);

            return ReadTokenIntrospectionDocument(copy[..written], diagnosticBody, response);
        }
        finally
        {
            copy.Clear();
        }
    }


    /// <summary>
    /// Whether an introspection endpoint's answer is an RFC 9457 problem: the <c>transport.content_type</c> metadata
    /// names it (<see cref="HttpResponseData.IsProblemJson"/>), or the received <c>Content-Type</c> field does, compared
    /// as <see cref="WellKnownMediaTypes.Application.IsProblemJson"/> compares, since a transport may carry the field
    /// alone.
    /// </summary>
    /// <param name="response">The answer as received.</param>
    /// <returns><see langword="true"/> when the answer is a problem.</returns>
    private static bool IsProblemJsonAnswer(HttpResponseData response) =>
        response.IsProblemJson
        || (response.Headers.TryGetSingle(WellKnownHttpHeaderNames.ContentType) is string contentType
            && WellKnownMediaTypes.Application.IsProblemJson(contentType));


    /// <summary>
    /// The refusal of an introspection endpoint's answer longer than <see cref="JwkJsonReader.MaximumDocumentLength"/>,
    /// answered before any buffer is rented for it.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-9">RFC 8259 Section 9</see>: "An implementation may set
    /// limits on the size of texts that it accepts."
    /// </remarks>
    /// <param name="diagnosticBody">The body the refusal carries: empty unless the body is an HTML or XML document.</param>
    /// <param name="response">The HTTP response the body came from, for the error's transport metadata.</param>
    /// <returns>The <see cref="OAuthMalformedResponse"/> failure.</returns>
    private static Result<TokenIntrospectionResult, OAuthParseError> RefuseOverLongIntrospectionResponse(
        string diagnosticBody,
        HttpResponseData response)
    {
        return Result.Failure<TokenIntrospectionResult, OAuthParseError>(
            new OAuthMalformedResponse(
                diagnosticBody,
                new DecisionSupport("The introspection response is longer than the document limit the client reads.")
                {
                    LikelyCause = "The server returned a body larger than any introspection response, or the body is not one.",
                    SpecificationReference = "RFC 8259 Section 9"
                }).WithTransportMetadata(response));
    }


    /// <summary>
    /// Reads an introspection endpoint's answer from its UTF-8 copy: the document held to
    /// <see cref="JwkJsonReader.IsWellFormedJsonDocument"/> and to being one object, then the authorization server's
    /// error when the object carries an <c>error</c> member, a refusal for a status other than 200 without one, and
    /// otherwise the object's members through <see cref="ReadTokenIntrospectionMembers"/>.
    /// </summary>
    /// <remarks>
    /// The <c>error</c>, <c>error_description</c> and <c>error_uri</c> members are read as the token response's are,
    /// at the top level of the object: an <c>error</c> that is empty or holds a char outside RFC 6749 Section 5.2's set
    /// makes the answer an <see cref="OAuthMalformedResponse"/>, an <c>error_description</c> outside the set and an
    /// <c>error_uri</c> outside its set or naming no <c>https</c> or <c>http</c> web page are read as absent.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "Values for the
    /// "error" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E."
    /// </remarks>
    /// <param name="json">The answer's UTF-8 copy.</param>
    /// <param name="diagnosticBody">The body a malformed-response refusal carries: empty unless the body is an HTML or XML document.</param>
    /// <param name="response">The HTTP response the body came from, for the error's transport metadata.</param>
    /// <returns>The introspection result, or the parse error.</returns>
    private static Result<TokenIntrospectionResult, OAuthParseError> ReadTokenIntrospectionDocument(
        ReadOnlySpan<byte> json,
        string diagnosticBody,
        HttpResponseData response)
    {
        if(!JwkJsonReader.IsWellFormedJsonDocument(json) || json.TrimStart(JsonWhitespaceUtf8) is not [(byte)'{', ..])
        {
            return Result.Failure<TokenIntrospectionResult, OAuthParseError>(
                new OAuthMalformedResponse(
                    diagnosticBody,
                    new DecisionSupport("The introspection response is not a well-formed JSON object, repeats a member name, or holds a string the reader refuses.")
                    {
                        LikelyCause = "The server returned a body that is not a JSON object, one two JSON readers could read differently " +
                                      "because it repeats a member name, or one with a string holding an unpaired surrogate, a noncharacter " +
                                      "or an escaped U+0000.",
                        SpecificationReference = "RFC 7662 Section 2.2, RFC 8259 Section 2 and Section 4, RFC 7493 Section 2.1, RFC 8259 Section 9"
                    }).WithTransportMetadata(response));
        }

        string? errorCode = JwkJsonReader.ExtractStringValue(json, OAuthRequestParameterNames.ErrorUtf8);
        if(errorCode is not null)
        {
            if(errorCode.Length == 0 || !IsErrorCharacterText(errorCode))
            {
                return Result.Failure<TokenIntrospectionResult, OAuthParseError>(
                    new OAuthMalformedResponse(
                        diagnosticBody,
                        new DecisionSupport("The introspection endpoint's error response carries an empty error code or one outside the characters RFC 6749 Section 5.2 permits.")
                        {
                            SpecificationReference = "RFC 6749 Section 5.2"
                        }).WithTransportMetadata(response));
            }

            string? errorDescription = JwkJsonReader.ExtractStringValue(json, OAuthRequestParameterNames.ErrorDescriptionUtf8);
            string? errorUri = JwkJsonReader.ExtractStringValue(json, ErrorUriUtf8);

            return BuildProtocolError<TokenIntrospectionResult>(
                errorCode,
                errorDescription is not null && IsErrorCharacterText(errorDescription) ? errorDescription : null,
                errorUri is not null && IsErrorUriCharacterText(errorUri) && IsWebPageUri(errorUri) ? errorUri : null,
                response,
                endpoint: "introspection",
                specReference: "RFC 7662 Section 2.3");
        }

        if(response.StatusCode != IntrospectionSuccessStatusCode)
        {
            return Result.Failure<TokenIntrospectionResult, OAuthParseError>(
                new OAuthMalformedResponse(
                    diagnosticBody,
                    new DecisionSupport("The introspection endpoint answered a status other than 200 without an error object.")
                    {
                        SpecificationReference = "RFC 7662 Section 2.2 and Section 2.3"
                    }).WithTransportMetadata(response));
        }

        return ReadTokenIntrospectionMembers(json, response);
    }


    /// <summary>The status of an introspection response, 200 (OK), the status RFC 7662 Section 2.2's examples answer with.</summary>
    private static int IntrospectionSuccessStatusCode => 200;


    /// <summary>The JSON insignificant white space bytes: space, horizontal tab, line feed and carriage return.</summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259 Section 2</see>: "ws = *( %x20 / %x09 /
    /// %x0A / %x0D )".
    /// </remarks>
    private static ReadOnlySpan<byte> JsonWhitespaceUtf8 => " \t\n\r"u8;


    /// <summary>
    /// Reads the members of one introspection response object, the one member reader of the plain answer: its input is
    /// one JSON object's text, braces included, already held to <see cref="JwkJsonReader.IsWellFormedJsonDocument"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>active</c> absent or not a JSON boolean makes the answer an <see cref="OAuthMalformedResponse"/>; <c>active</c>
    /// <see langword="false"/> answers <see cref="TokenIntrospectionResult.Inactive"/> and no other member is read, so
    /// nothing an authorization server writes beside it reaches the caller. With <c>active</c> <see langword="true"/>,
    /// each member below is read at the top level of the object, and a member present with another JSON type than its
    /// definition names is refused, never read as absent: <c>scope</c> a string held to RFC 6749 Appendix A.4
    /// (<see cref="IsScopeValue"/>); <c>client_id</c>, <c>username</c>, <c>sub</c>, <c>iss</c> and <c>jti</c> strings;
    /// <c>token_type</c> a string held to RFC 6749 Appendix A.13 (<see cref="IsTokenType"/>); <c>exp</c>, <c>iat</c> and
    /// <c>nbf</c> integers naming an instant <see cref="DateTimeOffset.FromUnixTimeSeconds"/> represents; <c>aud</c> one
    /// string, read as one entry, or an array of strings; <c>cnf</c> an object carrying a non-empty string <c>jkt</c>,
    /// read as <see cref="TokenIntrospectionResult.Confirmation"/>, a <c>jkt</c> beside other members enforced by the
    /// <c>jkt</c> alone. Each refusal is an <see cref="OAuthInvalidFieldValue"/> naming the member with an empty
    /// <see cref="OAuthInvalidFieldValue.ReceivedValue"/>, so a value is never echoed.
    /// </para>
    /// <para>
    /// A <c>cnf</c> carrying no <c>jkt</c> this resource enforces (one that is not an object, a certificate thumbprint
    /// <c>x5t#S256</c> alone, a member the reader does not understand, an empty or non-string <c>jkt</c>) is refused rather
    /// than read as a token bound to no key: the library's fail-closed reading, departing from
    /// <see href="https://www.rfc-editor.org/rfc/rfc7800#section-3.1">RFC 7800 Section 3.1</see>'s "However, in the
    /// absence of such requirements, all confirmation members that are not understood by implementations MUST be
    /// ignored.", since a resource that ignored such a member would serve a bound token as a bearer token. For the same
    /// reason the two readings of <c>token_type</c> that contradict the <c>cnf</c> are refused: a <c>token_type</c> other
    /// than <c>DPoP</c>, compared case-insensitively
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "Value is case
    /// insensitive."), beside a <c>cnf</c>, naming <c>token_type</c>; and <c>DPoP</c> with no <c>cnf</c>, naming
    /// <c>cnf</c>.
    /// </para>
    /// <para>
    /// Every other top-level member, <c>authorization_details</c> among them, is carried in
    /// <see cref="TokenIntrospectionResult.AdditionalClaims"/> under its name: a string as its decoded text, a boolean as
    /// a <see cref="bool"/>, an integer as a <see cref="long"/>, another number as a <see cref="double"/>, an object or
    /// array as <see cref="JsonScalarText.DecodeValue"/> decodes it; a member whose value is <c>null</c> carries no value
    /// and is not entered. <see cref="TokenIntrospectionResult.AuthorizationDetails"/> stays <see langword="null"/>.
    /// </para>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "active REQUIRED.
    /// Boolean indicator of whether or not the presented token is currently active.", "the authorization server SHOULD NOT
    /// include any additional information about an inactive token, including why the token is inactive." and "Specific
    /// implementations MAY extend this structure with their own service-specific response names as top-level members of
    /// this JSON object."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6">RFC 9449 Section 6</see>: "Resource servers MUST be
    /// able to reliably identify whether an access token is DPoP-bound and ascertain sufficient information to verify the
    /// binding to the public key of the DPoP proof (see Section 7.1)."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">Section 6.2</see>: "The hash is conveyed using the
    /// same cnf content with jkt member structure as the JWK Thumbprint confirmation method, described in Section 6.1, as
    /// a top-level member of the introspection response JSON." and "If the token_type member is included in the
    /// introspection response, it MUST contain the value DPoP."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">Section 7.2</see>: "such a protected resource MUST
    /// reject a DPoP-bound access token received as a bearer token per [RFC6750]."
    /// </para>
    /// </remarks>
    /// <param name="introspectionObject">The UTF-8 text of one JSON object, braces included.</param>
    /// <param name="response">The HTTP response the object came from, for the error's transport metadata.</param>
    /// <returns>The introspection result, or the parse error.</returns>
    internal static Result<TokenIntrospectionResult, OAuthParseError> ReadTokenIntrospectionMembers(
        ReadOnlySpan<byte> introspectionObject,
        HttpResponseData response)
    {
        if(!JwkJsonReader.TryExtractBooleanValue(introspectionObject, ActiveUtf8, out bool isActive))
        {
            return Result.Failure<TokenIntrospectionResult, OAuthParseError>(
                new OAuthMalformedResponse(
                    string.Empty,
                    new DecisionSupport("The introspection response carries no boolean active member.")
                    {
                        SpecificationReference = "RFC 7662 Section 2.2"
                    }).WithTransportMetadata(response));
        }

        //RFC 7662 Section 2.2: an inactive token is read as inactive, and nothing the answer carries beside active is read.
        if(!isActive)
        {
            return Result.Success<TokenIntrospectionResult, OAuthParseError>(TokenIntrospectionResult.Inactive);
        }

        if(ReadStringMember(introspectionObject, OAuthRequestParameterNames.ScopeUtf8, OAuthRequestParameterNames.Scope, out string? scope) is OAuthInvalidFieldValue scopeRefusal)
        {
            return RefuseIntrospectionMember(scopeRefusal, response);
        }

        if(scope is not null && !IsScopeValue(scope))
        {
            return RefuseIntrospectionMember(
                IntrospectionMemberRefusal(OAuthRequestParameterNames.Scope, ScopeGrammarReason, "RFC 6749 Appendix A.4"), response);
        }

        if(ReadStringMember(introspectionObject, OAuthRequestParameterNames.ClientIdUtf8, OAuthRequestParameterNames.ClientId, out string? clientId) is OAuthInvalidFieldValue clientIdRefusal)
        {
            return RefuseIntrospectionMember(clientIdRefusal, response);
        }

        if(ReadStringMember(introspectionObject, UsernameUtf8, Username, out string? username) is OAuthInvalidFieldValue usernameRefusal)
        {
            return RefuseIntrospectionMember(usernameRefusal, response);
        }

        if(ReadStringMember(introspectionObject, WellKnownJwtClaimNames.SubUtf8, WellKnownJwtClaimNames.Sub, out string? subject) is OAuthInvalidFieldValue subjectRefusal)
        {
            return RefuseIntrospectionMember(subjectRefusal, response);
        }

        if(ReadStringMember(introspectionObject, WellKnownJwtClaimNames.IssUtf8, WellKnownJwtClaimNames.Iss, out string? issuer) is OAuthInvalidFieldValue issuerRefusal)
        {
            return RefuseIntrospectionMember(issuerRefusal, response);
        }

        if(ReadStringMember(introspectionObject, WellKnownJwtClaimNames.JtiUtf8, WellKnownJwtClaimNames.Jti, out string? jwtId) is OAuthInvalidFieldValue jwtIdRefusal)
        {
            return RefuseIntrospectionMember(jwtIdRefusal, response);
        }

        if(ReadStringMember(introspectionObject, OAuthRequestParameterNames.TokenTypeUtf8, OAuthRequestParameterNames.TokenType, out string? tokenType) is OAuthInvalidFieldValue tokenTypeRefusal)
        {
            return RefuseIntrospectionMember(tokenTypeRefusal, response);
        }

        if(tokenType is not null && !IsTokenType(tokenType))
        {
            return RefuseIntrospectionMember(
                IntrospectionMemberRefusal(OAuthRequestParameterNames.TokenType, TokenTypeGrammarReason, "RFC 6749 Appendix A.13"), response);
        }

        if(ReadNumericDateMember(introspectionObject, WellKnownJwtClaimNames.ExpUtf8, WellKnownJwtClaimNames.Exp, out DateTimeOffset? expiresAt) is OAuthInvalidFieldValue expiresAtRefusal)
        {
            return RefuseIntrospectionMember(expiresAtRefusal, response);
        }

        if(ReadNumericDateMember(introspectionObject, WellKnownJwtClaimNames.IatUtf8, WellKnownJwtClaimNames.Iat, out DateTimeOffset? issuedAt) is OAuthInvalidFieldValue issuedAtRefusal)
        {
            return RefuseIntrospectionMember(issuedAtRefusal, response);
        }

        if(ReadNumericDateMember(introspectionObject, WellKnownJwtClaimNames.NbfUtf8, WellKnownJwtClaimNames.Nbf, out DateTimeOffset? notBefore) is OAuthInvalidFieldValue notBeforeRefusal)
        {
            return RefuseIntrospectionMember(notBeforeRefusal, response);
        }

        if(ReadAudienceMember(introspectionObject, out IReadOnlyList<string>? audience) is OAuthInvalidFieldValue audienceRefusal)
        {
            return RefuseIntrospectionMember(audienceRefusal, response);
        }

        if(ReadConfirmationMember(introspectionObject, out Server.ConfirmationMethod? confirmation) is OAuthInvalidFieldValue confirmationRefusal)
        {
            return RefuseIntrospectionMember(confirmationRefusal, response);
        }

        //RFC 9449 Section 6.2: a token_type beside a cnf is DPoP, and a DPoP token_type names a bound token whose cnf
        //the answer conveys; an answer whose two members disagree does not reliably identify the binding.
        bool isDpopTokenType = tokenType is not null && WellKnownAuthenticationSchemes.IsDPoP(tokenType);
        if(tokenType is not null && confirmation is not null && !isDpopTokenType)
        {
            return RefuseIntrospectionMember(
                IntrospectionMemberRefusal(OAuthRequestParameterNames.TokenType, TokenTypeBesideConfirmationReason, "RFC 9449 Section 6.2"), response);
        }

        if(isDpopTokenType && confirmation is null)
        {
            return RefuseIntrospectionMember(
                IntrospectionMemberRefusal(WellKnownJwtClaimNames.Cnf, DpopTokenTypeWithoutConfirmationReason, "RFC 9449 Section 6.2"), response);
        }

        return Result.Success<TokenIntrospectionResult, OAuthParseError>(new TokenIntrospectionResult
        {
            IsActive = true,
            Scope = scope,
            ClientId = clientId,
            Username = username,
            TokenType = tokenType,
            ExpiresAt = expiresAt,
            IssuedAt = issuedAt,
            NotBefore = notBefore,
            Subject = subject,
            Audience = audience,
            Issuer = issuer,
            JwtId = jwtId,
            Confirmation = confirmation,
            AdditionalClaims = ReadExtensionMembers(introspectionObject)
        });
    }


    /// <summary>The UTF-8 name of RFC 7662 Section 2.2's REQUIRED <c>active</c> member.</summary>
    private static ReadOnlySpan<byte> ActiveUtf8 => "active"u8;

    /// <summary>The UTF-8 name of RFC 7662 Section 2.2's <c>username</c> member.</summary>
    private static ReadOnlySpan<byte> UsernameUtf8 => "username"u8;

    /// <summary>The name of RFC 7662 Section 2.2's <c>username</c> member.</summary>
    private static string Username { get; } = "username";


    /// <summary>
    /// The top-level members <see cref="ReadTokenIntrospectionMembers"/> reads by name, compared ordinally; every other
    /// member is an extension member carried in <see cref="TokenIntrospectionResult.AdditionalClaims"/>.
    /// </summary>
    private static FrozenSet<string> NamedIntrospectionMembers { get; } =
        FrozenSet.ToFrozenSet(
        [
            "active",
            OAuthRequestParameterNames.Scope,
            OAuthRequestParameterNames.ClientId,
            Username,
            OAuthRequestParameterNames.TokenType,
            WellKnownJwtClaimNames.Exp,
            WellKnownJwtClaimNames.Iat,
            WellKnownJwtClaimNames.Nbf,
            WellKnownJwtClaimNames.Sub,
            WellKnownJwtClaimNames.Aud,
            WellKnownJwtClaimNames.Iss,
            WellKnownJwtClaimNames.Jti,
            WellKnownJwtClaimNames.Cnf
        ], StringComparer.Ordinal);


    /// <summary>
    /// The <see cref="OAuthInvalidFieldValue.Reason"/> of a <c>scope</c> outside RFC 6749 Appendix A.4, the reason of the
    /// token response's and the introspection response's refusal alike.
    /// </summary>
    private static string ScopeGrammarReason { get; } =
        "scope must be one or more scope-tokens, each one or more chars in %x21 / %x23-5B / %x5D-7E, separated by single spaces.";

    /// <summary>
    /// The <see cref="OAuthInvalidFieldValue.Reason"/> of a <c>token_type</c> outside RFC 6749 Appendix A.13, the reason of
    /// the token response's and the introspection response's refusal alike.
    /// </summary>
    private static string TokenTypeGrammarReason { get; } =
        "token_type must be one or more of \"-\", \".\", \"_\", an ASCII digit or an ASCII letter, or an RFC 3986 URI-reference.";

    /// <summary>The <see cref="OAuthInvalidFieldValue.Reason"/> of a <c>cnf</c> the resource cannot enforce.</summary>
    private static string ConfirmationReason { get; } =
        "cnf must be an object carrying a non-empty string jkt, the confirmation this resource enforces.";

    /// <summary>The <see cref="OAuthInvalidFieldValue.Reason"/> of a <c>token_type</c> other than <c>DPoP</c> beside a <c>cnf</c>.</summary>
    private static string TokenTypeBesideConfirmationReason { get; } =
        "token_type must be DPoP for a token whose cnf carries a jkt.";

    /// <summary>The <see cref="OAuthInvalidFieldValue.Reason"/> of a <c>token_type</c> of <c>DPoP</c> with no <c>cnf</c>.</summary>
    private static string DpopTokenTypeWithoutConfirmationReason { get; } =
        "A token_type of DPoP names a DPoP-bound token, and the response conveys no cnf jkt to check it against.";

    /// <summary>The earliest instant <see cref="DateTimeOffset.FromUnixTimeSeconds"/> represents, in seconds since the epoch.</summary>
    private static long MinimumRepresentableUnixSeconds { get; } = DateTimeOffset.MinValue.ToUnixTimeSeconds();

    /// <summary>The latest instant <see cref="DateTimeOffset.FromUnixTimeSeconds"/> represents, in seconds since the epoch.</summary>
    private static long MaximumRepresentableUnixSeconds { get; } = DateTimeOffset.MaxValue.ToUnixTimeSeconds();

    /// <summary>The bytes that close a JSON number at the top level of a well-formed object: a comma, a closing bracket or brace, or white space.</summary>
    private static SearchValues<byte> JsonNumberTerminators { get; } = SearchValues.Create(",}] \t\n\r"u8);


    /// <summary>
    /// The JSON kind of the value of the top-level member <paramref name="name"/>, read from the value's first byte, or
    /// <see langword="null"/> when the object carries no such member.
    /// </summary>
    /// <param name="json">The object's UTF-8 text, already held to well-formedness.</param>
    /// <param name="name">The member's UTF-8 name.</param>
    /// <returns>The value's kind, or <see langword="null"/> when the member is absent.</returns>
    private static JsonValueShape? ShapeOfMember(ReadOnlySpan<byte> json, ReadOnlySpan<byte> name)
    {
        int valueStart = JwkJsonReader.IndexOfValue(json, name);
        if(valueStart < 0 || valueStart >= json.Length)
        {
            return null;
        }

        return json[valueStart] switch
        {
            (byte)'"' => JsonValueShape.String,
            (byte)'{' => JsonValueShape.Object,
            (byte)'[' => JsonValueShape.Array,
            (byte)'t' or (byte)'f' => JsonValueShape.Boolean,
            (byte)'n' => JsonValueShape.Null,
            (byte)'-' or (>= (byte)'0' and <= (byte)'9') => JsonValueShape.Number,
            _ => JsonValueShape.Malformed
        };
    }


    /// <summary>
    /// Reads the top-level member <paramref name="name"/> as a JSON string: absent reads as <see langword="null"/>, a
    /// string as its decoded text, and a value of another kind is refused, never read as absent.
    /// </summary>
    /// <param name="json">The object's UTF-8 text.</param>
    /// <param name="name">The member's UTF-8 name.</param>
    /// <param name="fieldName">The member's name, which a refusal names.</param>
    /// <param name="value">The decoded text, or <see langword="null"/> when the member is absent or refused.</param>
    /// <returns>The refusal, or <see langword="null"/> when the member is absent or a string.</returns>
    private static OAuthInvalidFieldValue? ReadStringMember(
        ReadOnlySpan<byte> json, ReadOnlySpan<byte> name, string fieldName, out string? value)
    {
        value = null;
        JsonValueShape? shape = ShapeOfMember(json, name);
        if(shape is null)
        {
            return null;
        }

        value = shape == JsonValueShape.String ? JwkJsonReader.ExtractStringValue(json, name) : null;

        return value is null
            ? IntrospectionMemberRefusal(fieldName, $"{fieldName} must be a JSON string.", "RFC 7662 Section 2.2")
            : null;
    }


    /// <summary>
    /// Reads the top-level member <paramref name="name"/> as a JWT NumericDate: absent reads as <see langword="null"/>, an
    /// integer naming an instant <see cref="DateTimeOffset.FromUnixTimeSeconds"/> represents as that instant, and any other
    /// value (a string, a fraction, an exponent, an integer outside the range) is refused.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "exp OPTIONAL. Integer
    /// timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire, as
    /// defined in JWT [RFC7519]."
    /// </remarks>
    /// <param name="json">The object's UTF-8 text.</param>
    /// <param name="name">The member's UTF-8 name.</param>
    /// <param name="fieldName">The member's name, which a refusal names.</param>
    /// <param name="value">The instant, or <see langword="null"/> when the member is absent or refused.</param>
    /// <returns>The refusal, or <see langword="null"/> when the member is absent or an integer NumericDate.</returns>
    private static OAuthInvalidFieldValue? ReadNumericDateMember(
        ReadOnlySpan<byte> json, ReadOnlySpan<byte> name, string fieldName, out DateTimeOffset? value)
    {
        value = null;
        JsonValueShape? shape = ShapeOfMember(json, name);
        if(shape is null)
        {
            return null;
        }

        long seconds = 0;
        bool isRepresentable = shape == JsonValueShape.Number
            && JwkJsonReader.TryExtractLongValue(json, name, out seconds)
            && seconds >= MinimumRepresentableUnixSeconds
            && seconds <= MaximumRepresentableUnixSeconds;
        if(!isRepresentable)
        {
            return IntrospectionMemberRefusal(
                fieldName, $"{fieldName} must be an integer NumericDate naming a representable instant.", "RFC 7662 Section 2.2");
        }

        value = DateTimeOffset.FromUnixTimeSeconds(seconds);

        return null;
    }


    /// <summary>
    /// Reads the top-level <c>aud</c> member: absent reads as <see langword="null"/>, one string as a one-entry list, an
    /// array of strings as its entries in order, and any other value (an array holding a non-string entry among them) is
    /// refused.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "aud OPTIONAL.
    /// Service-specific string identifier or list of string identifiers representing the intended audience for this
    /// token, as defined in JWT [RFC7519]."
    /// </remarks>
    /// <param name="json">The object's UTF-8 text.</param>
    /// <param name="audience">The audience, or <see langword="null"/> when the member is absent or refused.</param>
    /// <returns>The refusal, or <see langword="null"/> when the member is absent, a string or an array of strings.</returns>
    private static OAuthInvalidFieldValue? ReadAudienceMember(ReadOnlySpan<byte> json, out IReadOnlyList<string>? audience)
    {
        audience = null;
        JsonValueShape? shape = ShapeOfMember(json, WellKnownJwtClaimNames.AudUtf8);
        if(shape is null)
        {
            return null;
        }

        audience = shape switch
        {
            JsonValueShape.String => JwkJsonReader.ExtractStringValue(json, WellKnownJwtClaimNames.AudUtf8) is string single ? [single] : null,
            JsonValueShape.Array => JwkJsonReader.ExtractStringArrayProperty(json, WellKnownJwtClaimNames.AudUtf8),
            _ => null
        };

        return audience is null
            ? IntrospectionMemberRefusal(WellKnownJwtClaimNames.Aud, "aud must be a string or an array of strings.", "RFC 7662 Section 2.2")
            : null;
    }


    /// <summary>
    /// Reads the top-level <c>cnf</c> member: absent reads as <see langword="null"/>, an object carrying a non-empty string
    /// <c>jkt</c> as the JWK Thumbprint confirmation, and any other value is refused with <see cref="ConfirmationReason"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "The hash is conveyed
    /// using the same cnf content with jkt member structure as the JWK Thumbprint confirmation method, described in
    /// Section 6.1, as a top-level member of the introspection response JSON."
    /// </remarks>
    /// <param name="json">The object's UTF-8 text.</param>
    /// <param name="confirmation">The confirmation, or <see langword="null"/> when the member is absent or refused.</param>
    /// <returns>The refusal, or <see langword="null"/> when the member is absent or carries a readable <c>jkt</c>.</returns>
    private static OAuthInvalidFieldValue? ReadConfirmationMember(ReadOnlySpan<byte> json, out Server.ConfirmationMethod? confirmation)
    {
        confirmation = null;
        JsonValueShape? shape = ShapeOfMember(json, WellKnownJwtClaimNames.CnfUtf8);
        if(shape is null)
        {
            return null;
        }

        string? thumbprint = shape == JsonValueShape.Object
            ? JwkJsonReader.ExtractStringValue(JwkJsonReader.ExtractObjectContent(json, WellKnownJwtClaimNames.CnfUtf8), WellKnownJwtClaimNames.JwkThumbprintUtf8)
            : null;
        if(string.IsNullOrEmpty(thumbprint))
        {
            return IntrospectionMemberRefusal(WellKnownJwtClaimNames.Cnf, ConfirmationReason, "RFC 9449 Section 6.2");
        }

        confirmation = new Server.ConfirmationMethod { JwkThumbprint = thumbprint };

        return null;
    }


    /// <summary>
    /// Reads every top-level member <see cref="NamedIntrospectionMembers"/> does not name, keyed by its decoded name, each
    /// value decoded by its kind (<see cref="ReadExtensionValue"/>); a member whose value is <c>null</c> is not entered.
    /// </summary>
    /// <param name="json">The object's UTF-8 text.</param>
    /// <returns>The extension members, or <see langword="null"/> when the object carries none.</returns>
    private static Dictionary<string, object>? ReadExtensionMembers(ReadOnlySpan<byte> json)
    {
        Dictionary<string, object>? members = null;
        foreach(string name in JwkJsonReader.GetTopLevelKeyNames(json))
        {
            if(NamedIntrospectionMembers.Contains(name))
            {
                continue;
            }

            if(ReadExtensionValue(json, Encoding.UTF8.GetBytes(name)) is object value)
            {
                members ??= new Dictionary<string, object>(StringComparer.Ordinal);
                members[name] = value;
            }
        }

        return members;
    }


    /// <summary>
    /// The value of the top-level member <paramref name="name"/> decoded by its kind: a string as its decoded text, a
    /// boolean as a <see cref="bool"/>, an integer as a <see cref="long"/>, another number as a <see cref="double"/>, and an
    /// object or array as <see cref="JsonScalarText.DecodeValue"/> decodes its text.
    /// </summary>
    /// <param name="json">The object's UTF-8 text.</param>
    /// <param name="name">The member's UTF-8 name.</param>
    /// <returns>The decoded value, or <see langword="null"/> for <c>null</c>.</returns>
    private static object? ReadExtensionValue(ReadOnlySpan<byte> json, ReadOnlySpan<byte> name) => ShapeOfMember(json, name) switch
    {
        JsonValueShape.String => JwkJsonReader.ExtractStringValue(json, name),
        JsonValueShape.Boolean => JwkJsonReader.TryExtractBooleanValue(json, name, out bool isTrue) ? isTrue : null,
        JsonValueShape.Number => ReadNumberValue(json, name),
        JsonValueShape.Object => JwkJsonReader.ExtractObjectAsString(json, name) is string objectText ? JsonScalarText.DecodeValue(objectText) : null,
        JsonValueShape.Array => JwkJsonReader.ExtractArrayAsString(json, name) is string arrayText ? JsonScalarText.DecodeValue(arrayText) : null,
        _ => null
    };


    /// <summary>
    /// The value of the top-level number member <paramref name="name"/>: a <see cref="long"/> for an integer in its range,
    /// otherwise the number's text decoded by <see cref="JsonScalarText.DecodeValue"/>.
    /// </summary>
    /// <param name="json">The object's UTF-8 text.</param>
    /// <param name="name">The member's UTF-8 name.</param>
    /// <returns>The number.</returns>
    private static object? ReadNumberValue(ReadOnlySpan<byte> json, ReadOnlySpan<byte> name)
    {
        if(JwkJsonReader.TryExtractLongValue(json, name, out long integer))
        {
            return integer;
        }

        ReadOnlySpan<byte> rest = json[JwkJsonReader.IndexOfValue(json, name)..];
        int numberEnd = rest.IndexOfAny(JsonNumberTerminators);

        return JsonScalarText.DecodeValue(Encoding.UTF8.GetString(numberEnd < 0 ? rest : rest[..numberEnd]));
    }


    /// <summary>
    /// The refusal of an introspection response member outside its definition: an <see cref="OAuthInvalidFieldValue"/>
    /// naming the member with <paramref name="reason"/> and an empty <see cref="OAuthInvalidFieldValue.ReceivedValue"/>,
    /// so the value, which may describe a credential, is never echoed.
    /// </summary>
    /// <param name="fieldName">The member refused.</param>
    /// <param name="reason">The fixed reason naming the member's definition.</param>
    /// <param name="specificationReference">The clause that defines the member.</param>
    /// <returns>The refusal.</returns>
    private static OAuthInvalidFieldValue IntrospectionMemberRefusal(string fieldName, string reason, string specificationReference) =>
        new(
            fieldName,
            string.Empty,
            reason,
            new DecisionSupport($"The introspection response contained a {fieldName} value outside its definition.")
            {
                SpecificationReference = specificationReference
            });


    /// <summary>The failure carrying <paramref name="refusal"/> with <paramref name="response"/>'s transport metadata.</summary>
    /// <param name="refusal">The refusal.</param>
    /// <param name="response">The HTTP response the object came from.</param>
    /// <returns>The failure.</returns>
    private static Result<TokenIntrospectionResult, OAuthParseError> RefuseIntrospectionMember(
        OAuthInvalidFieldValue refusal, HttpResponseData response) =>
        Result.Failure<TokenIntrospectionResult, OAuthParseError>(refusal.WithTransportMetadata(response));


    /// <summary>
    /// The UTF-8 name of the RFC 6749 Section 5.2 <c>error_uri</c> member of a token endpoint's error
    /// response, which <see cref="ReadTokenResponse"/> reads at the top level.
    /// </summary>
    private static ReadOnlySpan<byte> ErrorUriUtf8 => "error_uri"u8;


    /// <summary>
    /// Reads a token endpoint response's members from its UTF-8 copy once the document is well-formed:
    /// the RFC 6749 Section 5.2 error members, or the Section 5.1 success members and the granted
    /// <c>authorization_details</c>, each at the top level of the response object only.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The document is held to <see cref="JwkJsonReader.IsWellFormedJsonDocument"/> before any member is
    /// read, as the Pre-Authorized Code wallet holds its Token Response, so a repeated member cannot make
    /// this reader and another consumer of the same body read different values; a body it refuses is an
    /// <see cref="OAuthMalformedResponse"/>. Every member is then read with the depth-0 readers of
    /// <see cref="JwkJsonReader"/>: <c>error</c>, <c>error_description</c>, <c>error_uri</c>,
    /// <c>access_token</c>, <c>token_type</c>, <c>refresh_token</c>, <c>scope</c> and <c>id_token</c> as
    /// JSON strings through <see cref="JwkJsonReader.ExtractStringValue"/> (a member whose value is not a
    /// string reads as absent), <c>expires_in</c> through <see cref="JwkJsonReader.TryExtractLongValue"/>
    /// (a value that is not an integer, or lies outside the range of <see cref="int"/>, reads as absent;
    /// zero or a negative value is an <see cref="OAuthInvalidFieldValue"/>), and
    /// <c>authorization_details</c> through <see cref="GrantedCredentialAuthorizationReader.TryRead"/>
    /// (a malformed member is an <see cref="OAuthInvalidFieldValue"/> naming it, which the
    /// authorization-code client answers as <c>invalid_response</c>, its received value empty). A string
    /// value is read with its JSON escapes decoded, and the members <c>error</c>,
    /// <c>error_description</c>, <c>error_uri</c>, <c>access_token</c>, <c>token_type</c>,
    /// <c>refresh_token</c>, <c>scope</c> and <c>id_token</c> are then held to their grammars, since a
    /// decoded value can hold any char:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>
    ///     an <c>error</c> that is empty (Appendix A.7 <c>error = 1*NQSCHAR</c>) or holds a char outside
    ///     <c>%x20-21 / %x23-5B / %x5D-7E</c> (<see cref="IsErrorCharacterText"/>) makes the response an
    ///     <see cref="OAuthMalformedResponse"/>; an <c>error_description</c> holding such a char, or an
    ///     <c>error_uri</c> holding a char outside <c>%x21 / %x23-5B / %x5D-7E</c>
    ///     (<see cref="IsErrorUriCharacterText"/>) or that is not a URI-reference that is an <c>https</c>
    ///     or <c>http</c> URI whose authority is a non-empty host with an optional port and no userinfo
    ///     (<see cref="IsWebPageUri"/>), is read as absent and the
    ///     protocol error stands with its code;
    ///   </description></item>
    ///   <item><description>
    ///     an <c>access_token</c> holding a char outside <c>%x20-7E</c>
    ///     (<see cref="IsVisibleCharacterText"/>), a present <c>refresh_token</c> that is empty or holds
    ///     such a char, a <c>token_type</c> that is neither a type name nor an RFC 3986 URI-reference
    ///     (<see cref="IsTokenType"/>), a present <c>scope</c> outside Appendix A.4
    ///     (<see cref="IsScopeValue"/>), or a present <c>id_token</c> that is empty or holds a char outside
    ///     the JWS Compact Serialization's base64url chars and periods
    ///     (<see cref="IsCompactSerializationText"/>), is refused as an <see cref="OAuthInvalidFieldValue"/>
    ///     naming the member, with a fixed reason and an empty received value, so the value is never
    ///     echoed; an empty <c>access_token</c> or <c>token_type</c> is refused as an
    ///     <see cref="OAuthMalformedResponse"/> before its grammar is tested.
    ///   </description></item>
    /// </list>
    /// <para>
    /// The <c>access_token</c> is held to Appendix A.12's <c>1*VSCHAR</c> here, since this parser serves
    /// clients that carry the token in places other than an <c>Authorization</c> header; the
    /// Pre-Authorized Code wallet, which presents it as that header's credential, holds it to RFC 9110's
    /// <c>token68</c> as well. <c>expires_in</c> is held as stated above. <c>id_token</c> is held to its
    /// alphabet only and is otherwise surfaced unvalidated: it is the input of the ID Token validator,
    /// <see cref="Oidc10IdTokenValidator.ValidateAsync"/>, which refuses a value that is not a compact
    /// JWS as <see cref="JwsAccessTokenValidationFailureReason.Malformed"/>.
    /// </para>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "The parameters are serialized into a JSON structure by adding each parameter at the highest
    /// structure level."
    /// And: "Values for the "error" parameter MUST NOT include characters outside the set %x20-21 /
    /// %x23-5B / %x5D-7E."
    /// And: "Values for the "error_description" parameter MUST NOT include characters outside the set
    /// %x20-21 / %x23-5B / %x5D-7E."
    /// And: "Values for the "error_uri" parameter MUST conform to the URI-reference syntax and thus MUST
    /// NOT include characters outside the set %x21 / %x23-5B / %x5D-7E."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.7">RFC 6749 Appendix A.7</see>:
    /// "error             = 1*NQSCHAR".
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.4">RFC 6749 Appendix A.4</see>:
    /// "scope       = scope-token *( SP scope-token )" and "scope-token = 1*NQCHAR".
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.12">RFC 6749 Appendix A.12</see>:
    /// "access-token = 1*VSCHAR".
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", "type-name  = 1*name-char" and
    /// "name-char  = "-" / "." / "_" / DIGIT / ALPHA".
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.17">RFC 6749 Appendix A.17</see>:
    /// "refresh-token = 1*VSCHAR".
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "It is a non-empty array of objects, as defined in Section 7 of [RFC9396]."
    /// </para>
    /// </remarks>
    /// <param name="tokenJson">The Token Response body's UTF-8 copy.</param>
    /// <param name="diagnosticBody">The body a malformed-response refusal carries: empty unless the body is an HTML or XML document.</param>
    /// <param name="response">The HTTP response the body came from, for the error's transport metadata.</param>
    /// <returns>The parsed Token Response, or the parse error.</returns>
    private static Result<TokenResponse, OAuthParseError> ReadTokenResponse(
        ReadOnlySpan<byte> tokenJson,
        string diagnosticBody,
        HttpResponseData response)
    {
        if(!JwkJsonReader.IsWellFormedJsonDocument(tokenJson))
        {
            return Result.Failure<TokenResponse, OAuthParseError>(
                new OAuthMalformedResponse(
                    diagnosticBody,
                    new DecisionSupport("The token response is not well-formed JSON, repeats a member name, or holds a string the reader refuses.")
                    {
                        LikelyCause = "The server returned a body that is not a JSON text, one two JSON readers could read differently " +
                                      "because it repeats a member name, or one with a string holding an unpaired surrogate, a noncharacter " +
                                      "or an escaped U+0000.",
                        SpecificationReference = "RFC 8259 Section 2 and Section 4, RFC 7493 Section 2.1, RFC 8259 Section 9"
                    }).WithTransportMetadata(response));
        }

        string? errorCode = JwkJsonReader.ExtractStringValue(tokenJson, OAuthRequestParameterNames.ErrorUtf8);
        if(errorCode is not null)
        {
            //RFC 6749 Section 5.2 and Appendix A.7: an error code that is empty or holds a char outside its
            //set is no error code the client can act on, so the response is malformed; a description outside
            //its set, or a URI outside its set or naming no http or https web page, is read as absent.
            if(errorCode.Length == 0 || !IsErrorCharacterText(errorCode))
            {
                return Result.Failure<TokenResponse, OAuthParseError>(
                    new OAuthMalformedResponse(
                        diagnosticBody,
                        new DecisionSupport("The token endpoint's error response carries an empty error code or one outside the characters RFC 6749 Section 5.2 permits.")
                        {
                            SpecificationReference = "RFC 6749 Section 5.2"
                        }).WithTransportMetadata(response));
            }

            string? errorDescription = JwkJsonReader.ExtractStringValue(tokenJson, OAuthRequestParameterNames.ErrorDescriptionUtf8);
            string? errorUri = JwkJsonReader.ExtractStringValue(tokenJson, ErrorUriUtf8);

            return BuildProtocolError<TokenResponse>(
                errorCode,
                errorDescription is not null && IsErrorCharacterText(errorDescription) ? errorDescription : null,
                errorUri is not null && IsErrorUriCharacterText(errorUri) && IsWebPageUri(errorUri) ? errorUri : null,
                response,
                endpoint: "token",
                specReference: "RFC 6749 §5.2");
        }

        string? accessToken = JwkJsonReader.ExtractStringValue(tokenJson, OAuthRequestParameterNames.AccessTokenUtf8);
        if(string.IsNullOrEmpty(accessToken))
        {
            return Result.Failure<TokenResponse, OAuthParseError>(
                new OAuthMalformedResponse(
                    diagnosticBody,
                    new DecisionSupport("The token response did not contain an access_token.")
                    {
                        LikelyCause = "The server did not return a valid token response. " +
                                      "The response may be an error without using the " +
                                      "standard error field.",
                        SpecificationReference = "RFC 6749 §5.1"
                    }).WithTransportMetadata(response));
        }

        if(!IsVisibleCharacterText(accessToken))
        {
            return RefuseMemberOutsideItsGrammar(
                OAuthRequestParameterNames.AccessToken,
                "access_token must be one or more chars in %x20-7E.",
                "RFC 6749 Appendix A.12",
                response);
        }

        string? tokenType = JwkJsonReader.ExtractStringValue(tokenJson, OAuthRequestParameterNames.TokenTypeUtf8);
        if(string.IsNullOrEmpty(tokenType))
        {
            return Result.Failure<TokenResponse, OAuthParseError>(
                new OAuthMalformedResponse(
                    diagnosticBody,
                    new DecisionSupport("The token response did not contain a token_type.")
                    {
                        LikelyCause = "The server returned an access_token without a " +
                                      "token_type, which is not permitted by RFC 6749 §5.1.",
                        SpecificationReference = "RFC 6749 §5.1"
                    }).WithTransportMetadata(response));
        }

        if(!IsTokenType(tokenType))
        {
            return RefuseMemberOutsideItsGrammar(
                OAuthRequestParameterNames.TokenType,
                TokenTypeGrammarReason,
                "RFC 6749 Appendix A.13",
                response);
        }

        int? expiresIn = null;
        if(JwkJsonReader.TryExtractLongValue(tokenJson, OAuthRequestParameterNames.ExpiresInUtf8, out long expiresInValue)
            && expiresInValue is >= int.MinValue and <= int.MaxValue)
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

            expiresIn = (int)expiresInValue;
        }

        //OID4VCI 1.0 Section 6.2: the openid_credential authorizations the response granted are read
        //by the reader the Pre-Authorized Code wallet uses; a malformed member fails the whole parse.
        if(!GrantedCredentialAuthorizationReader.TryRead(
            tokenJson, out IReadOnlyList<GrantedCredentialAuthorization> grantedAuthorizations))
        {
            //The member's text is the server's to shape and may carry a credential, so it is not echoed.
            return Result.Failure<TokenResponse, OAuthParseError>(
                new OAuthInvalidFieldValue(
                    OAuthRequestParameterNames.AuthorizationDetails,
                    string.Empty,
                    "authorization_details must be a non-empty array of objects, each carrying a string type; "
                    + "an openid_credential entry carries a credential_configuration_id and a non-empty "
                    + "credential_identifiers, none of them empty or white space.",
                    new DecisionSupport("The token response contained a malformed authorization_details value.")
                    {
                        SpecificationReference = "OID4VCI 1.0 Section 6.2"
                    }).WithTransportMetadata(response));
        }

        //RFC 6749 Appendix A.17: a present refresh_token is one or more chars in %x20-7E; an absent one
        //stays absent.
        string? refreshToken = JwkJsonReader.ExtractStringValue(tokenJson, OAuthRequestParameterNames.RefreshTokenUtf8);
        if(refreshToken is not null && (refreshToken.Length == 0 || !IsVisibleCharacterText(refreshToken)))
        {
            return RefuseMemberOutsideItsGrammar(
                OAuthRequestParameterNames.RefreshToken,
                "refresh_token must be one or more chars in %x20-7E.",
                "RFC 6749 Appendix A.17",
                response);
        }

        string? scope = JwkJsonReader.ExtractStringValue(tokenJson, OAuthRequestParameterNames.ScopeUtf8);
        if(scope is not null && !IsScopeValue(scope))
        {
            return RefuseMemberOutsideItsGrammar(
                OAuthRequestParameterNames.Scope,
                ScopeGrammarReason,
                "RFC 6749 Appendix A.4",
                response);
        }

        //RFC 7515 Section 7.1: a present id_token is held to the JWS Compact Serialization's alphabet only;
        //the ID Token validator reads everything else.
        string? idToken = JwkJsonReader.ExtractStringValue(tokenJson, OAuthRequestParameterNames.IdTokenUtf8);
        if(idToken is not null && !IsCompactSerializationText(idToken))
        {
            return RefuseMemberOutsideItsGrammar(
                OAuthRequestParameterNames.IdToken,
                "id_token must be one or more base64url chars (\"-\", \"_\", an ASCII digit or an ASCII letter) "
                + "or periods.",
                "RFC 7515 Section 7.1",
                response);
        }

        return Result.Success<TokenResponse, OAuthParseError>(
            new TokenResponse
            {
                AccessToken = accessToken,
                TokenType = tokenType,
                ExpiresIn = expiresIn,
                RefreshToken = refreshToken,
                Scope = scope,
                IdToken = idToken,
                GrantedCredentialAuthorizations = grantedAuthorizations
            });
    }


    /// <summary>
    /// The refusal of a token endpoint response longer than
    /// <see cref="JwkJsonReader.MaximumDocumentLength"/>, which is answered before any buffer is rented
    /// for it.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-9">RFC 8259 Section 9</see>:
    /// "An implementation may set limits on the size of texts that it accepts."
    /// </remarks>
    /// <param name="diagnosticBody">The body the refusal carries: empty unless the body is an HTML or XML document.</param>
    /// <param name="response">The HTTP response the body came from, for the error's transport metadata.</param>
    /// <returns>The <see cref="OAuthMalformedResponse"/> failure.</returns>
    private static Result<TokenResponse, OAuthParseError> RefuseOverLongTokenResponse(
        string diagnosticBody,
        HttpResponseData response)
    {
        return Result.Failure<TokenResponse, OAuthParseError>(
            new OAuthMalformedResponse(
                diagnosticBody,
                new DecisionSupport("The token response is longer than the document limit the client reads.")
                {
                    LikelyCause = "The server returned a body larger than any Token Response, or the body is not a Token Response.",
                    SpecificationReference = "RFC 8259 Section 9"
                }).WithTransportMetadata(response));
    }


    /// <summary>
    /// Whether a refused token endpoint response body is an HTML or XML document: with a leading byte
    /// order mark and white space stripped, its first char is <c>&lt;</c>. Such a body, an error page a
    /// gateway or a server framework wrote, is carried in the refusal for diagnostics; every other
    /// refused body, a JSON text, a form-encoded body, plain text or anything else, may hold a token
    /// under any spelling and is carried as <see cref="string.Empty"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.3">RFC 6749 Section 10.3</see>:
    /// "Access token credentials (as well as any confidential access token attributes) MUST be kept
    /// confidential in transit and storage, and only shared among the authorization server, the resource
    /// servers the access token is valid for, and the client to whom the access token is issued."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.4">RFC 6749 Section 10.4</see>:
    /// "Refresh tokens MUST be kept confidential in transit and storage, and shared only among the
    /// authorization server and the client to whom the refresh tokens were issued."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 Section 8.1</see>:
    /// "Implementations MUST NOT add a byte order mark (U+FEFF) to the beginning of a
    /// networked-transmitted JSON text."
    /// </remarks>
    /// <param name="body">The trimmed response body.</param>
    /// <returns><see langword="true"/> when the body's first char past a byte order mark and white space is <c>&lt;</c>.</returns>
    private static bool IsHtmlOrXmlDocument(ReadOnlySpan<char> body) =>
        body.TrimStart(ByteOrderMark).TrimStart() is ['<', ..];


    /// <summary>
    /// The byte order mark, U+FEFF, which <see cref="IsHtmlOrXmlDocument"/> strips before it tests a
    /// body's first char: <see cref="MemoryExtensions.Trim(ReadOnlySpan{char})"/> keeps it, since it is not
    /// white space.
    /// </summary>
    private static char ByteOrderMark => '\uFEFF';


    /// <summary>
    /// The chars of an RFC 6749 Appendix A.13 <c>name-char</c>: <c>-</c>, <c>.</c>, <c>_</c>, the ASCII
    /// digits and the ASCII letters.
    /// </summary>
    private static SearchValues<char> TypeNameCharacters { get; } =
        SearchValues.Create("-._0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");


    /// <summary>
    /// Whether every char of a value is an RFC 6749 Appendix A <c>VSCHAR</c>, the grammar of an
    /// <c>access_token</c> (Appendix A.12) and a <c>refresh_token</c> (Appendix A.17): a token holding a
    /// control char, a char above <c>%x7E</c> or a lone surrogate is outside it, and is never composed
    /// into a header.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A">RFC 6749 Appendix A</see>:
    /// "VSCHAR     = %x20-7E".
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.12">RFC 6749 Appendix A.12</see>:
    /// "access-token = 1*VSCHAR".
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.17">RFC 6749 Appendix A.17</see>:
    /// "refresh-token = 1*VSCHAR".
    /// </remarks>
    /// <param name="value">The decoded member value.</param>
    /// <returns><see langword="true"/> when no char of the value lies outside <c>%x20-7E</c>.</returns>
    internal static bool IsVisibleCharacterText(ReadOnlySpan<char> value) =>
        value.IndexOfAnyExceptInRange(' ', '~') < 0;


    /// <summary>
    /// Whether a value is an RFC 6749 Appendix A.13 <c>type-name</c>: one or more of <c>-</c>, <c>.</c>,
    /// <c>_</c>, an ASCII digit or an ASCII letter.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", "type-name  = 1*name-char" and
    /// "name-char  = "-" / "." / "_" / DIGIT / ALPHA".
    /// </remarks>
    /// <param name="value">The decoded <c>token_type</c> value.</param>
    /// <returns><see langword="true"/> when the value is a type name.</returns>
    private static bool IsTokenTypeName(ReadOnlySpan<char> value) =>
        !value.IsEmpty && value.IndexOfAnyExcept(TypeNameCharacters) < 0;


    /// <summary>
    /// Whether a <c>token_type</c> value is an RFC 6749 Appendix A.13 <c>token-type</c>: a type name
    /// (<see cref="IsTokenTypeName"/>), or an RFC 3986 <c>URI-reference</c> as the span recognizer
    /// <see cref="IsUriReference"/> reads it (its chars, at most one <c>#</c>, a well-formed scheme or a
    /// relative reference whose first segment holds no colon, brackets only inside an authority). The
    /// Token Response parser and the Pre-Authorized Code wallet hold their <c>token_type</c> to it. An
    /// empty value is no token type.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", "type-name  = 1*name-char" and
    /// "name-char  = "-" / "." / "_" / DIGIT / ALPHA".
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.1">RFC 3986 Section 4.1</see>:
    /// "URI-reference = URI / relative-ref".
    /// </remarks>
    /// <param name="value">The decoded <c>token_type</c> value.</param>
    /// <returns><see langword="true"/> when the value is a type name or a URI-reference.</returns>
    internal static bool IsTokenType(string value) =>
        IsTokenTypeName(value) || IsUriReference(value);


    /// <summary>
    /// Whether a value is an RFC 3986 Section 4.1 <c>URI-reference</c>, read over its chars and its
    /// delimiters: (a) every char is unreserved, a gen-delim, a sub-delim, or a <c>%</c> followed by two
    /// hex digits (<see cref="IsUriCharacterText"/>); (b) the value holds at most one <c>#</c>; (c) it is a
    /// URI, its first segment's colon closing a scheme of <c>ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )</c>
    /// (<see cref="IsScheme"/>), or a relative reference whose first segment holds no colon; (d) <c>[</c>
    /// and <c>]</c> stand only inside an authority, between <c>//</c> and the authority's end at the next
    /// <c>/</c>, <c>?</c>, <c>#</c> or the value's end; (e) the value is non-empty. The authority's inner
    /// structure is not read further: brackets need not form an IP-literal and the port need not be
    /// digits.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.1">RFC 3986 Section 4.1</see>:
    /// "URI-reference = URI / relative-ref".
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3">RFC 3986 Section 3</see>:
    /// "URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]".
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.1">RFC 3986 Section 3.1</see>:
    /// "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )".
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">RFC 3986 Section 4.2</see>:
    /// "relative-ref  = relative-part [ "?" query ] [ "#" fragment ]" and "A path segment that contains
    /// a colon character (e.g., "this:that") cannot be used as the first segment of a relative-path
    /// reference, as it would be mistaken for a scheme name."
    /// </remarks>
    /// <param name="value">The decoded value.</param>
    /// <returns><see langword="true"/> when the value is a URI-reference by the five rules.</returns>
    private static bool IsUriReference(ReadOnlySpan<char> value)
    {
        if(value.IsEmpty || !IsUriCharacterText(value) || value.Count('#') > 1)
        {
            return false;
        }

        //The first segment runs to the first "/", "?" or "#"; a colon in it closes a scheme, since a
        //relative-path reference's first segment holds none.
        int firstSegmentEnd = value.IndexOfAny('/', '?', '#');
        ReadOnlySpan<char> firstSegment = firstSegmentEnd < 0 ? value : value[..firstSegmentEnd];
        int schemeEnd = firstSegment.IndexOf(':');
        if(schemeEnd >= 0 && !IsScheme(firstSegment[..schemeEnd]))
        {
            return false;
        }

        //The hier-part or relative-part follows the scheme's colon; brackets stand only in its authority.
        ReadOnlySpan<char> part = value[(schemeEnd + 1)..];
        if(!part.StartsWith("//", StringComparison.Ordinal))
        {
            return part.IndexOfAny('[', ']') < 0;
        }

        ReadOnlySpan<char> afterAuthorityStart = part[2..];
        int authorityEnd = afterAuthorityStart.IndexOfAny('/', '?', '#');

        return authorityEnd < 0 || afterAuthorityStart[authorityEnd..].IndexOfAny('[', ']') < 0;
    }


    /// <summary>
    /// Whether every char of a value is an RFC 3986 unreserved char, a gen-delim or a sub-delim
    /// (<see cref="UriReferenceCharacters"/>), or a <c>%</c> followed by two hex digits: the chars a
    /// URI-reference is written in.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2.1">RFC 3986 Section 2.1</see>:
    /// "pct-encoded = "%" HEXDIG HEXDIG".
    /// </remarks>
    /// <param name="value">The decoded value.</param>
    /// <returns><see langword="true"/> when every char is one a URI-reference may hold.</returns>
    private static bool IsUriCharacterText(ReadOnlySpan<char> value)
    {
        int index = 0;
        while(index < value.Length)
        {
            if(value[index] != '%')
            {
                if(!UriReferenceCharacters.Contains(value[index]))
                {
                    return false;
                }

                index++;
                continue;
            }

            if(index + 2 >= value.Length || !char.IsAsciiHexDigit(value[index + 1]) || !char.IsAsciiHexDigit(value[index + 2]))
            {
                return false;
            }

            index += 3;
        }

        return true;
    }


    /// <summary>
    /// Whether a value is an RFC 3986 Section 3.1 <c>scheme</c>: an ASCII letter followed by ASCII
    /// letters, digits, <c>+</c>, <c>-</c> or <c>.</c>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.1">RFC 3986 Section 3.1</see>:
    /// "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )".
    /// </remarks>
    /// <param name="value">The chars before the first segment's colon.</param>
    /// <returns><see langword="true"/> when the value is a scheme.</returns>
    private static bool IsScheme(ReadOnlySpan<char> value) =>
        value is [var first, ..] && char.IsAsciiLetter(first) && value[1..].IndexOfAnyExcept(SchemeCharacters) < 0;


    /// <summary>
    /// The chars of an RFC 3986 URI-reference other than <c>%</c>: the unreserved chars
    /// (<c>ALPHA / DIGIT / "-" / "." / "_" / "~"</c>), the gen-delims
    /// (<c>":" / "/" / "?" / "#" / "[" / "]" / "@"</c>) and the sub-delims
    /// (<c>"!" / "$" / "&amp;" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="</c>).
    /// </summary>
    private static SearchValues<char> UriReferenceCharacters { get; } =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=");


    /// <summary>
    /// The chars of an RFC 3986 <c>scheme</c> past its first letter: the ASCII letters and digits,
    /// <c>+</c>, <c>-</c> and <c>.</c>.
    /// </summary>
    private static SearchValues<char> SchemeCharacters { get; } =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-.");


    /// <summary>
    /// Whether a present <c>id_token</c> is written in the JWS Compact Serialization's alphabet: one or
    /// more base64url chars (<c>A-Z</c>, <c>a-z</c>, <c>0-9</c>, <c>-</c>, <c>_</c>) or periods. Nothing
    /// else of the ID Token is read here; <see cref="Oidc10IdTokenValidator.ValidateAsync"/> reads it.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-7.1">RFC 7515 Section 7.1</see>:
    /// "The JWS Compact Serialization represents digitally signed or MACed content as a compact, URL-safe
    /// string. This string is: BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) ||
    /// '.' || BASE64URL(JWS Signature)".
    /// </remarks>
    /// <param name="value">The decoded <c>id_token</c> value.</param>
    /// <returns><see langword="true"/> when the value is non-empty and every char is in the alphabet.</returns>
    private static bool IsCompactSerializationText(ReadOnlySpan<char> value) =>
        !value.IsEmpty && value.IndexOfAnyExcept(CompactSerializationCharacters) < 0;


    /// <summary>
    /// The chars of a JWS Compact Serialization: the base64url alphabet and the period.
    /// </summary>
    private static SearchValues<char> CompactSerializationCharacters { get; } =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.");


    /// <summary>
    /// Whether an <c>error_uri</c> identifies a web page: the value is a URI-reference
    /// (<see cref="IsUriReference"/>) whose scheme is <c>https</c> or <c>http</c>, compared without case,
    /// with a query, a fragment, both or neither, and (a) its hier-part starts with <c>//</c>; (b) its
    /// authority, from <c>//</c> to the next <c>/</c>, <c>?</c>, <c>#</c> or the value's end, is not
    /// empty; (c) the authority holds no <c>@</c>, so it carries no userinfo; (d) the authority is a
    /// non-empty host with an optional port: a host that starts with <c>[</c> runs to the first <c>]</c>,
    /// holds an IPv6 address between the brackets, and its <c>]</c> is the authority's last char or is
    /// followed by <c>:</c> and digits only; any other host is not empty and holds no <c>[</c>, no
    /// <c>]</c> and no <c>:</c>, so the authority holds at most one <c>:</c>, which is followed by digits
    /// only. An IPvFuture literal and a zone identifier are read as absent, as this library's reading
    /// for a web page's URI. Any other
    /// value, a char or delimiter no URI-reference holds, another scheme such as <c>javascript</c>,
    /// <c>file</c> or <c>data</c>, a relative reference, a hier-part without an authority, an empty
    /// authority, an authority behind a userinfo, or a host or port outside that shape, is read as absent.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "error_uri OPTIONAL. A URI identifying a human-readable web page with information about the
    /// error, used to provide the client developer with additional information about the error."
    /// And: "Values for the "error_uri" parameter MUST conform to the URI-reference syntax and thus MUST
    /// NOT include characters outside the set %x21 / %x23-5B / %x5D-7E."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.9">RFC 6749 Appendix A.9</see>:
    /// "error-uri         = URI-reference".
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3">RFC 3986 Section 3</see>:
    /// "URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]".
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.1">RFC 9110 Section 4.2.1</see>:
    /// "http-URI = "http" "://" authority path-abempty [ "?" query ]" and "A sender MUST NOT generate an
    /// "http" URI with an empty host identifier.  A recipient that processes such a URI reference MUST
    /// reject it as invalid."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.2">RFC 9110 Section 4.2.2</see>:
    /// "https-URI = "https" "://" authority path-abempty [ "?" query ]" and "A sender MUST NOT generate an
    /// "https" URI with an empty host identifier.  A recipient that processes such a URI reference MUST
    /// reject it as invalid."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">RFC 9110 Section 4.2.4</see>:
    /// "Before making use of an "http" or "https" URI reference received from an untrusted source, a
    /// recipient SHOULD parse for userinfo and treat its presence as an error; it is likely being used to
    /// obscure the authority for the sake of phishing attacks."
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2">RFC 3986 Section 3.2</see>:
    /// "authority   = [ userinfo "@" ] host [ ":" port ]".
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2">RFC 3986 Section 3.2.2</see>:
    /// "host        = IP-literal / IPv4address / reg-name",
    /// "IP-literal = "[" ( IPv6address / IPvFuture  ) "]"" and
    /// "reg-name    = *( unreserved / pct-encoded / sub-delims )".
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.3">RFC 3986 Section 3.2.3</see>:
    /// "port        = *DIGIT".
    /// </remarks>
    /// <param name="value">The decoded <c>error_uri</c> value.</param>
    /// <returns>
    /// <see langword="true"/> when the value is a URI-reference that is an <c>https</c> or <c>http</c>
    /// URI with a non-empty authority that is a non-empty host with an optional port and no userinfo.
    /// </returns>
    private static bool IsWebPageUri(string value)
    {
        ReadOnlySpan<char> text = value;
        if(!IsUriReference(text))
        {
            return false;
        }

        //A URI-reference whose first segment's colon closes the scheme "https" or "http" is a URI of
        //that scheme; IsUriReference refused a first segment whose colon closes no scheme.
        bool isHttps = text.StartsWith("https:", StringComparison.OrdinalIgnoreCase);
        if(!isHttps && !text.StartsWith("http:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        //RFC 9110 Sections 4.2.1 and 4.2.2: an http or https URI is the scheme, "://" and an authority.
        ReadOnlySpan<char> hierPart = text[(isHttps ? "https:".Length : "http:".Length)..];
        if(!hierPart.StartsWith("//", StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> authority = hierPart[2..];
        int authorityEnd = authority.IndexOfAny('/', '?', '#');
        if(authorityEnd >= 0)
        {
            authority = authority[..authorityEnd];
        }

        //RFC 9110 Sections 4.2.1 and 4.2.2: a URI with an empty host identifier is rejected as invalid.
        //RFC 9110 Section 4.2.4: an "@" in the authority closes a userinfo, which is treated as an error.
        if(authority.IsEmpty || authority.IndexOf('@') >= 0)
        {
            return false;
        }

        //RFC 9110 Sections 4.2.1 and 4.2.2: the host is not empty. RFC 3986 Section 3.2: the authority
        //is the host and an optional ":" port of digits. A host that starts with "[" runs to the first
        //"]" and holds an IPv6 address between the brackets (an IPvFuture literal and a zone identifier
        //are read as absent); any other host is not empty and holds no bracket and no ":", and its port
        //follows the one ":".
        ReadOnlySpan<char> afterHost;
        if(authority is ['[', ..])
        {
            int literalEnd = authority.IndexOf(']');
            if(literalEnd < 2)
            {
                return false;
            }

            ReadOnlySpan<char> literal = authority[1..literalEnd];
            if(literal.IndexOf('%') >= 0
                || literal.IndexOf(':') < 0
                || !System.Net.IPAddress.TryParse(literal, out _))
            {
                return false;
            }

            afterHost = authority[(literalEnd + 1)..];
        }
        else
        {
            if(authority.IndexOfAny('[', ']') >= 0)
            {
                return false;
            }

            int portStart = authority.LastIndexOf(':');
            ReadOnlySpan<char> host = portStart < 0 ? authority : authority[..portStart];
            if(host.IsEmpty || host.IndexOf(':') >= 0)
            {
                return false;
            }

            afterHost = portStart < 0 ? ReadOnlySpan<char>.Empty : authority[portStart..];
        }

        return afterHost is [] || (afterHost is [':', .. var port] && port.IndexOfAnyExceptInRange('0', '9') < 0);
    }


    /// <summary>
    /// Whether a <c>scope</c> value is an RFC 6749 Appendix A.4 <c>scope</c>: one or more scope tokens,
    /// each one or more chars in <c>%x21 / %x23-5B / %x5D-7E</c> (printable ASCII without the space, the
    /// quotation mark and the reverse solidus), separated by single spaces.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.4">RFC 6749 Appendix A.4</see>:
    /// "scope       = scope-token *( SP scope-token )" and "scope-token = 1*NQCHAR".
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A">RFC 6749 Appendix A</see>:
    /// "NQCHAR     = %x21 / %x23-5B / %x5D-7E".
    /// </remarks>
    /// <param name="value">The decoded <c>scope</c> value.</param>
    /// <returns><see langword="true"/> when the value is within the grammar.</returns>
    private static bool IsScopeValue(ReadOnlySpan<char> value) =>
        value is [not ' ', ..] and [.., not ' ']
        && !value.Contains("  ", StringComparison.Ordinal)
        && value.IndexOfAnyExceptInRange(' ', '~') < 0
        && value.IndexOfAny('"', '\\') < 0;


    /// <summary>
    /// Whether every char of an <c>error</c> or <c>error_description</c> value lies in RFC 6749 Section
    /// 5.2's set <c>%x20-21 / %x23-5B / %x5D-7E</c>: printable ASCII without the quotation mark and the
    /// reverse solidus. Both readers of a Token Error Response hold the set: this parser and the
    /// Pre-Authorized Code wallet's error read.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B /
    /// %x5D-7E." And: "Values for the "error_description" parameter MUST NOT include characters outside
    /// the set %x20-21 / %x23-5B / %x5D-7E."
    /// </remarks>
    /// <param name="value">The decoded member value.</param>
    /// <returns><see langword="true"/> when no char of the value lies outside the set.</returns>
    internal static bool IsErrorCharacterText(ReadOnlySpan<char> value) =>
        value.IndexOfAnyExceptInRange(' ', '~') < 0 && value.IndexOfAny('"', '\\') < 0;


    /// <summary>
    /// Whether every char of an <c>error_uri</c> value lies in RFC 6749 Section 5.2's set
    /// <c>%x21 / %x23-5B / %x5D-7E</c>: printable ASCII without the space, the quotation mark and the
    /// reverse solidus.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error_uri" parameter MUST conform to the URI-reference syntax and thus MUST NOT
    /// include characters outside the set %x21 / %x23-5B / %x5D-7E."
    /// </remarks>
    /// <param name="value">The decoded member value.</param>
    /// <returns><see langword="true"/> when no char of the value lies outside the set.</returns>
    private static bool IsErrorUriCharacterText(ReadOnlySpan<char> value) =>
        value.IndexOfAnyExceptInRange('!', '~') < 0 && value.IndexOfAny('"', '\\') < 0;


    /// <summary>
    /// The refusal of a Token Response member whose value lies outside its RFC 6749 Appendix A grammar:
    /// an <see cref="OAuthInvalidFieldValue"/> naming the member with a fixed reason and an empty
    /// <see cref="OAuthInvalidFieldValue.ReceivedValue"/>, so the value, which may be a credential, is never
    /// echoed.
    /// </summary>
    /// <param name="fieldName">The member whose value is refused.</param>
    /// <param name="reason">The fixed reason naming the grammar.</param>
    /// <param name="specificationReference">The clause that defines the grammar.</param>
    /// <param name="response">The HTTP response the body came from, for the error's transport metadata.</param>
    /// <returns>The <see cref="OAuthInvalidFieldValue"/> failure.</returns>
    private static Result<TokenResponse, OAuthParseError> RefuseMemberOutsideItsGrammar(
        string fieldName,
        string reason,
        string specificationReference,
        HttpResponseData response)
    {
        return Result.Failure<TokenResponse, OAuthParseError>(
            new OAuthInvalidFieldValue(
                fieldName,
                string.Empty,
                reason,
                new DecisionSupport($"The token response contained a {fieldName} value outside its grammar.")
                {
                    SpecificationReference = specificationReference
                }).WithTransportMetadata(response));
    }


    /// <summary>
    /// Builds the <see cref="OAuthProtocolError"/> for an OAuth error response from the values its
    /// caller read: an empty <c>error_description</c> carries no description, and an empty or
    /// non-absolute <c>error_uri</c> carries no URI.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "error_uri OPTIONAL. A URI identifying a human-readable web page with information about the
    /// error, used to provide the client developer with additional information about the error.
    /// Values for the "error_uri" parameter MUST conform to the URI-reference syntax and thus MUST NOT
    /// include characters outside the set %x21 / %x23-5B / %x5D-7E."
    /// A URI-reference may be a relative reference; such a value is dropped, since the client holds no
    /// base URI the server named to resolve it against.
    /// </remarks>
    /// <typeparam name="T">The success type of the parse the error answers.</typeparam>
    /// <param name="errorCode">The <c>error</c> member's value.</param>
    /// <param name="description">The <c>error_description</c> member's value, or <see langword="null"/> when absent.</param>
    /// <param name="errorUriText">The <c>error_uri</c> member's value, or <see langword="null"/> when absent.</param>
    /// <param name="response">The HTTP response the error came from, for the error's transport metadata.</param>
    /// <param name="endpoint">The endpoint name the summary names.</param>
    /// <param name="specReference">The clause the error response is defined by.</param>
    /// <returns>The <see cref="OAuthProtocolError"/> failure.</returns>
    private static Result<T, OAuthParseError> BuildProtocolError<T>(
        string errorCode,
        string? description,
        string? errorUriText,
        HttpResponseData response,
        string endpoint,
        string specReference)
    {
        string? serverDescription = string.IsNullOrEmpty(description) ? null : description;

        Uri? errorUri = null;
        if(!string.IsNullOrEmpty(errorUriText))
        {
            _ = Uri.TryCreate(errorUriText, UriKind.Absolute, out errorUri);
        }

        DecisionSupport support = BuildProtocolErrorSupport(
            errorCode, serverDescription, endpoint, specReference);

        return Result.Failure<T, OAuthParseError>(
            new OAuthProtocolError(errorCode, support, serverDescription, errorUri)
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
