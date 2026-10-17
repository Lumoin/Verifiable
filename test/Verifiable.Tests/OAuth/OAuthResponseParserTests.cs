using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="OAuthResponseParsers"/> covering RFC 9126 §2.2,
/// RFC 6749 §5.1/5.2, and RFC 9457 response shapes.
/// </summary>
[TestClass]
internal sealed class OAuthResponseParsersTests
{
    /// <summary>The test context whose cancellation token bounds each loopback exchange.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A PAR endpoint answer is read as an RFC 9457 problem only when its <c>Content-Type</c>, received
    /// over the real loopback wire, names the problem details media type; a value that merely contains
    /// the text <c>application/problem+json</c> names another media type.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3">RFC 9457 Section 3</see>:
    /// "When serialized in a JSON document, that format is identified with the "application/problem+json" media type."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 Section 8.3.1</see>:
    /// "The type and subtype tokens are case-insensitive."
    /// </summary>
    /// <param name="contentType">The literal <c>Content-Type</c> the server sends.</param>
    /// <param name="isExpectedProblem">Whether the value names the problem details media type.</param>
    [TestMethod]
    [DataRow("application/problem+json", true)]
    [DataRow("Application/Problem+JSON; charset=utf-8", true)]
    [DataRow("application/problem+jsonx", false)]
    [DataRow("text/plain; note=\"application/problem+json\"", false)]
    [DataRow("text/plain", false)]
    public async Task ProblemJsonIsRecognizedByMediaTypeNotBySubstring(string contentType, bool isExpectedProblem)
    {
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(
            (request, cancellationToken) => Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 400,
                ContentType = contentType,
                Body = /*lang=json,strict*/ """{"type":"invalid_request","detail":"code_challenge is required","instance":"urn:uuid:abc-123"}"""
            }),
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient client = LoopbackTls.CreatePinnedHttpClient(host.Certificate);

        HttpResponseData received = await HttpClientTransport.SendFormPostAsync(
            client,
            host.BaseAddress,
            new Dictionary<string, string> { ["client_id"] = "problem-media-type-client" },
            OutgoingHeaders.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The application's transport delegate lifts the received Content-Type into the
        //documented metadata key, as HttpResponseData leaves that capture to the application.
        string? wireContentType = received.Headers.TryGetSingle(WellKnownHttpHeaderNames.ContentType);
        Assert.IsNotNull(wireContentType, "The loopback response must carry a Content-Type.");
        HttpResponseData response = received with
        {
            TransportMetadata = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [HttpResponseDataKeys.ContentType] = wireContentType
            }
        };

        Result<ParResponse, OAuthParseError> result = OAuthResponseParsers.ParseParResponse(response);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(isExpectedProblem, response.IsProblemJson,
            $"Content-Type \"{wireContentType}\" names the problem details media type: {isExpectedProblem}.");
        Assert.AreEqual(isExpectedProblem, result.Error is OAuthProtocolError { Support.SpecificationReference: "RFC 9457" },
            $"Content-Type \"{wireContentType}\" is parsed as an RFC 9457 problem: {isExpectedProblem}.");
    }


    [TestMethod]
    public void ParseParResponseSucceedsForMinimalValidResponse()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}""");

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("urn:ietf:params:oauth:request_uri:abc",
            result.Value.RequestUri.ToString());
        Assert.AreEqual(60, result.Value.ExpiresIn);
    }

    [TestMethod]
    public void ParseParResponseSucceedsWithWhitespacePadding()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{ "request_uri" : "urn:ietf:params:oauth:request_uri:ws", "expires_in" : 90 }""");

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(90, result.Value.ExpiresIn);
    }

    [TestMethod]
    public void ParseParResponseSucceedsWhenFieldsAreReversed()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"expires_in":45,"request_uri":"urn:ietf:params:oauth:request_uri:rev"}""");

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(45, result.Value.ExpiresIn);
    }


    //PAR error cases — OAuth protocol errors.

    [TestMethod]
    public void ParseParResponseReturnsProtocolErrorForInvalidRequest()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"error":"invalid_request","error_description":"code_challenge missing"}""",
            statusCode: 400);

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsFalse(result.IsSuccess);
        OAuthProtocolError pe =
            Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_request", pe.ErrorCode);
        Assert.AreEqual("code_challenge missing", pe.ErrorDescription);
    }

    [TestMethod]
    public void ParseParResponseProtocolErrorCarriesDecisionSupportGuidance()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"error":"invalid_request"}""",
            statusCode: 400);

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsFalse(result.IsSuccess);
        OAuthProtocolError pe =
            Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.IsNotNull(pe.Support.LikelyCause,
            "invalid_request must carry a likely cause explanation.");
        Assert.IsNotNull(pe.Support.ActionableGuidance,
            "invalid_request must carry actionable guidance.");
        Assert.AreEqual("RFC 9126 §2.3", pe.Support.SpecificationReference);
    }

    [TestMethod]
    public void ParseParResponseProtocolErrorSurfacesStatusCodeInContext()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"error":"invalid_client"}""",
            statusCode: 401);

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsFalse(result.IsSuccess);
        string? statusCode = result.Error.Support.Context?[HttpResponseDataKeys.StatusCode];
        Assert.AreEqual("401", statusCode,
            "HTTP status code must be surfaced in DecisionSupport context.");
    }

    [TestMethod]
    public void ParseParResponseProtocolErrorCarriesTraceParentAsCorrelationId()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"error":"server_error"}""",
            statusCode: 500,
            metadata: new Dictionary<string, string>
            {
                [HttpResponseDataKeys.TraceParent] = "00-abc123-def456-01"
            });

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual("00-abc123-def456-01", result.Error.Support.CorrelationId,
            "traceparent must become the CorrelationId on the DecisionSupport.");
    }



    [TestMethod]
    public void ParseParResponseReturnsMalformedForEmptyBody()
    {
        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(Respond(string.Empty));

        Assert.IsFalse(result.IsSuccess);
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
    }

    [TestMethod]
    public void ParseParResponseReturnsMalformedWhenRequestUriMissing()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"expires_in":60}""");

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsFalse(result.IsSuccess);
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
    }

    [TestMethod]
    public void ParseParResponseReturnsInvalidFieldValueForNegativeExpiresIn()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":-1}""");

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsFalse(result.IsSuccess);
        OAuthInvalidFieldValue ifv =
            Assert.IsInstanceOfType<OAuthInvalidFieldValue>(result.Error);
        Assert.AreEqual("expires_in", ifv.FieldName);
        Assert.AreEqual("-1", ifv.ReceivedValue);
    }

    [TestMethod]
    public void ParseParResponseReturnsInvalidFieldValueForRelativeRequestUri()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"request_uri":"/relative/path","expires_in":60}""");

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsFalse(result.IsSuccess);
        OAuthInvalidFieldValue ifv =
            Assert.IsInstanceOfType<OAuthInvalidFieldValue>(result.Error);
        Assert.AreEqual("request_uri", ifv.FieldName);
    }


    //PAR RFC 9457 problem+json.

    [TestMethod]
    public void ParseParResponseHandlesProblemJsonResponse()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"type":"invalid_request","detail":"code_challenge is required","instance":"urn:uuid:abc-123"}""",
            statusCode: 400,
            contentType: WellKnownMediaTypes.Application.ProblemJson);

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsFalse(result.IsSuccess);
        OAuthProtocolError pe =
            Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_request", pe.ErrorCode);
        Assert.AreEqual("code_challenge is required", pe.ErrorDescription);
        Assert.AreEqual("urn:uuid:abc-123", pe.Support.CorrelationId,
            "RFC 9457 instance must become the CorrelationId.");
    }



    [TestMethod]
    public void ParseTokenResponseSucceedsForMinimalValidResponse()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"tok123","token_type":"Bearer","expires_in":3600}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("tok123", result.Value.AccessToken);
        Assert.AreEqual("Bearer", result.Value.TokenType);
        Assert.AreEqual(3600, result.Value.ExpiresIn);
    }

    [TestMethod]
    public void ParseTokenResponseSucceedsWithOptionalFields()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"at","token_type":"DPoP","expires_in":900,"refresh_token":"rt","scope":"openid"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("rt", result.Value.RefreshToken);
        Assert.AreEqual("openid", result.Value.Scope);
    }

    [TestMethod]
    public void ParseTokenResponseSucceedsWithoutExpiresIn()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"at","token_type":"Bearer"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsNull(result.Value.ExpiresIn,
            "expires_in must be null when not present in the response.");
    }



    [TestMethod]
    public void ParseTokenResponseReturnsProtocolErrorForAccessDenied()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"error":"access_denied","error_description":"User cancelled"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess);
        OAuthProtocolError pe =
            Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("access_denied", pe.ErrorCode);
        Assert.AreEqual("RFC 6749 §5.2", pe.Support.SpecificationReference);
    }

    [TestMethod]
    public void ParseTokenResponseReturnsMalformedWhenAccessTokenMissing()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"token_type":"Bearer","expires_in":3600}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess);
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
    }

    [TestMethod]
    public void ParseTokenResponseReturnsInvalidFieldValueForZeroExpiresIn()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"at","token_type":"Bearer","expires_in":0}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess);
        OAuthInvalidFieldValue ifv =
            Assert.IsInstanceOfType<OAuthInvalidFieldValue>(result.Error);
        Assert.AreEqual("expires_in", ifv.FieldName);
    }

    [TestMethod]
    public void ParseTokenResponseHandlesProblemJsonResponse()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"type":"invalid_grant","detail":"Authorization code expired","instance":"urn:uuid:xyz-789"}""",
            statusCode: 400,
            contentType: WellKnownMediaTypes.Application.ProblemJson);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess);
        OAuthProtocolError pe =
            Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", pe.ErrorCode);
        Assert.AreEqual("urn:uuid:xyz-789", pe.Support.CorrelationId);
    }



    /// <summary>
    /// RFC 6749 §5.1 has a token response's parameters serialized "into a JSON structure by adding each parameter at the
    /// highest structure level": an otherwise valid token response carried inside an extension object, with no parameter at the
    /// top level, is no token response, and an <c>error</c> an extension object carries is no error response either. Each is
    /// refused as malformed, nothing read from the nested object.
    /// </summary>
    /// <param name="body">The response body.</param>
    [TestMethod]
    [DataRow(/*lang=json,strict*/ """{"ext":{"access_token":"nested-access-token","token_type":"Bearer","expires_in":3600}}""", DisplayName = "A token response inside an extension object")]
    [DataRow(/*lang=json,strict*/ """{"ext":{"error":"invalid_grant","error_description":"nested"}}""", DisplayName = "An error inside an extension object")]
    [DataRow(/*lang=json,strict*/ """{"ext":[{"access_token":"nested-access-token","token_type":"Bearer"}]}""", DisplayName = "A token response inside an extension array")]
    public void ParseTokenResponseReadsNoParameterANestedValueCarries(string body)
    {
        var result = OAuthResponseParsers.ParseTokenResponse(Respond(body), DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess, "A response carrying its parameters below the top level is refused.");
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error, "Nothing nested is read as the response's parameter.");
    }


    /// <summary>
    /// A token response carrying an extension object whose members compete with its own, written before them: each parameter is
    /// read from the top level alone, the object's <c>access_token</c>, <c>token_type</c>, <c>refresh_token</c>,
    /// <c>id_token</c>, <c>issued_token_type</c> and <c>error</c> never in their place, so a reader of the same body as the
    /// JSON it is reads the very values this parser answers.
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseReadsTheTopLevelParametersBesideACompetingExtensionObject()
    {
        var body = /*lang=json,strict*/ """
            {"ext":{"access_token":"nested-access-token","token_type":"DPoP","refresh_token":"nested-refresh-token","id_token":"nested-id-token","issued_token_type":"urn:nested","error":"invalid_grant","expires_in":1},
             "access_token":"top-access-token","token_type":"Bearer","refresh_token":"top-refresh-token","id_token":"top-id-token",
             "issued_token_type":"urn:ietf:params:oauth:token-type:id-jag","expires_in":900}
            """;

        var result = OAuthResponseParsers.ParseTokenResponse(Respond(body), DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess, $"The top-level response is read; refused by {(result.IsSuccess ? null : result.Error.Support.Summary)}.");
        Assert.AreEqual("top-access-token", result.Value.AccessToken);
        Assert.AreEqual("Bearer", result.Value.TokenType);
        Assert.AreEqual("top-refresh-token", result.Value.RefreshToken);
        Assert.AreEqual("top-id-token", result.Value.IdToken);
        Assert.AreEqual(WellKnownTokenTypeIdentifiers.IdJag, result.Value.IssuedTokenType);
        Assert.AreEqual(900, result.Value.ExpiresIn);
    }


    /// <summary>
    /// RFC 8259 §7: a member name or a string value may be spelled with escapes, and the parameter is what the escapes decode
    /// to, decoded once. A response naming <c>access_token</c> and <c>token_type</c> through escapes is read by those names,
    /// and an access token, an ID Token and a refresh token spelled with <c>\/</c> and <c>\u002e</c> are answered decoded,
    /// never as the backslashes the body spells.
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseReadsEscapedNamesAndValuesDecodedOnce()
    {
        var body = /*lang=json,strict*/ """{"acc\u0065ss_token":"access\/token\u002eone","token_\u0074ype":"Bearer","id_token":"head\u002ebody\u002esig","refresh_token":"refresh\\u002e"}""";

        var result = OAuthResponseParsers.ParseTokenResponse(Respond(body), DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess, $"The escaped names are the parameters' names; refused by {(result.IsSuccess ? null : result.Error.Support.Summary)}.");
        Assert.AreEqual("access/token.one", result.Value.AccessToken, "The access token is its decoded text.");
        Assert.AreEqual("Bearer", result.Value.TokenType);
        Assert.AreEqual("head.body.sig", result.Value.IdToken, "The ID Token is its decoded text.");
        Assert.AreEqual(@"refresh\u002e", result.Value.RefreshToken, "An escaped backslash is decoded once, so the escape it begins is never decoded again.");
    }


    /// <summary>
    /// A body that names a parameter in more than one way is refused as malformed (RFC 8259 §4: "the behavior of software that
    /// receives such an object is unpredictable"), as is a body that is no JSON object or no well-formed JSON at all, and an
    /// <c>access_token</c> spelled as a string naming no Unicode text (RFC 8259 §8.2) is no access token.
    /// </summary>
    /// <param name="body">The response body.</param>
    [TestMethod]
    [DataRow(/*lang=json*/ """{"access_token":"first","access_token":"second","token_type":"Bearer"}""", DisplayName = "An access_token named twice")]
    [DataRow(/*lang=json*/ """{"access_token":"at","token_type":"Bearer","ext":{"note":"one","note":"two"}}""", DisplayName = "A name repeated in an extension object")]
    [DataRow(/*lang=json,strict*/ """["access_token","at","token_type","Bearer"]""", DisplayName = "An array")]
    [DataRow("{\"access_token\":\"at\",\"token_type\":\"Bearer\"", DisplayName = "An object never closed")]
    [DataRow(/*lang=json*/ """{"access_token":"\uD800","token_type":"Bearer"}""", DisplayName = "An access_token naming an unpaired surrogate")]
    public void ParseTokenResponseRefusesABodyNamingNoOneAccessToken(string body)
    {
        var result = OAuthResponseParsers.ParseTokenResponse(Respond(body), DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess, "No access token is read from the body.");
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
    }


    /// <summary>
    /// The pushed authorization response is read from the top level alone as the token response is (RFC 9126 §2.2): a
    /// <c>request_uri</c> and <c>expires_in</c> an extension object carries are no parameters, and the escaped spelling of the
    /// top-level ones is read decoded.
    /// </summary>
    [TestMethod]
    public void ParseParResponseReadsTheTopLevelParametersAlone()
    {
        var nested = OAuthResponseParsers.ParseParResponse(Respond(
            /*lang=json,strict*/ """{"ext":{"request_uri":"urn:ietf:params:oauth:request_uri:nested","expires_in":60}}"""));

        Assert.IsFalse(nested.IsSuccess, "A request_uri nested in an extension object is no parameter.");
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(nested.Error);

        var escaped = OAuthResponseParsers.ParseParResponse(Respond(
            /*lang=json,strict*/ """{"ext":{"request_uri":"urn:ietf:params:oauth:request_uri:nested"},"request\u005furi":"urn:ietf:params:oauth:request\u005furi:top","expires_in":60}"""));

        Assert.IsTrue(escaped.IsSuccess, "The escaped top-level request_uri is read.");
        Assert.AreEqual("urn:ietf:params:oauth:request_uri:top", escaped.Value.RequestUri.OriginalString, "The top-level value is read, decoded.");
    }


    [TestMethod]
    public void AllKnownOAuthErrorCodesProduceLikelyCause()
    {
        string[] knownCodes =
        [
            "invalid_request", "invalid_client", "unauthorized_client",
            "access_denied", "unsupported_response_type", "invalid_scope",
            "server_error", "temporarily_unavailable"
        ];

        foreach(string code in knownCodes)
        {
            HttpResponseData response = Respond(
                $"{{\"error\":\"{code}\"}}",
                statusCode: 400);

            Result<ParResponse, OAuthParseError> result =
                OAuthResponseParsers.ParseParResponse(response);

            Assert.IsFalse(result.IsSuccess);
            OAuthProtocolError pe =
                Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
            Assert.IsNotNull(pe.Support.LikelyCause,
                $"Error code '{code}' must carry a LikelyCause in DecisionSupport.");
        }
    }



    private static HttpResponseData Respond(
        string body,
        int statusCode = 200,
        string? contentType = null,
        IReadOnlyDictionary<string, string>? metadata = null)
    {
        Dictionary<string, string>? transport = null;

        if(contentType is not null || metadata is not null)
        {
            transport = [];
            if(contentType is not null)
            {
                transport[HttpResponseDataKeys.ContentType] = contentType;
            }
            if(metadata is not null)
            {
                foreach(KeyValuePair<string, string> kvp in metadata)
                {
                    transport[kvp.Key] = kvp.Value;
                }
            }
        }

        return new HttpResponseData
        {
            Body = body,
            StatusCode = statusCode,
            TransportMetadata = transport
        };
    }
}
