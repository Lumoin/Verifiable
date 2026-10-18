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
    [DataRow(
        /*lang=json,strict*/ """{"ext":{"access_token":"nested-access-token","token_type":"Bearer","expires_in":3600}}""",
        DisplayName = "A token response inside an extension object")]
    [DataRow(
        /*lang=json,strict*/ """{"ext":{"error":"invalid_grant","error_description":"nested"}}""",
        DisplayName = "An error inside an extension object")]
    [DataRow(
        /*lang=json,strict*/ """{"ext":[{"access_token":"nested-access-token","token_type":"Bearer"}]}""",
        DisplayName = "A token response inside an extension array")]
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
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, result.Value.TokenType);
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
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, result.Value.TokenType);
        Assert.AreEqual("head.body.sig", result.Value.IdToken, "The ID Token is its decoded text.");
        Assert.AreEqual(@"refresh\u002e", result.Value.RefreshToken, "An escaped backslash is decoded once, so the escape it begins is never decoded again.");
    }


    /// <summary>
    /// A body that is no JSON object or no well-formed JSON at all is refused as malformed, each also when it repeats a name:
    /// the repetition of a body that is no well-formed object is never its reason.
    /// </summary>
    /// <param name="body">The response body.</param>
    [TestMethod]
    [DataRow(/*lang=json,strict*/ """["access_token","at","token_type","Bearer"]""", DisplayName = "An array")]
    [DataRow("{\"access_token\":\"at\",\"token_type\":\"Bearer\"", DisplayName = "An object never closed")]
    [DataRow(
        """{"access_token":"at","token_type":"Bearer"}{"access_token":"again"}""",
        DisplayName = "Two top-level values")]
    [DataRow(
        /*lang=json*/ """[{"access_token":"first","access_token":"second","token_type":"Bearer"}]""",
        DisplayName = "An array holding an object that repeats access_token")]
    [DataRow(
        "{\"access_token\":\"first\",\"access_token\":\"second\",\"token_type\":\"Bearer\"",
        DisplayName = "An object never closed that repeats access_token")]
    public void ParseTokenResponseRefusesABodyThatIsNoOneObjectAsMalformed(string body)
    {
        var result = OAuthResponseParsers.ParseTokenResponse(Respond(body), DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess, "No access token is read from the body.");
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error, "The body is no well-formed object.");
    }


    /// <summary>
    /// RFC 8259 §4: the names within an object SHOULD be unique, and "the behavior of software that receives such an object is
    /// unpredictable". A token response that is one well-formed object but repeats a name, at the top level or in an extension
    /// object, is refused for the repetition itself, naming the name and the depth of the object repeating it, never as a body
    /// that is not well-formed JSON; its summary is composed from those facts and carries none of the values the body holds.
    /// </summary>
    /// <param name="body">The response body.</param>
    /// <param name="expectedName">The repeated name.</param>
    /// <param name="expectedDepth">The depth of the object repeating it.</param>
    [TestMethod]
    [DataRow(
        /*lang=json*/ """{"access_token":"first-credential-text","access_token":"second-credential-text","token_type":"Bearer"}""",
        "access_token",
        1,
        DisplayName = "An access_token named twice")]
    [DataRow(
        /*lang=json*/ """{"access_token":"first-credential-text","token_type":"Bearer","ext":{"note":"one","note":"two"}}""",
        "note",
        2,
        DisplayName = "A name repeated in an extension object")]
    public void ParseTokenResponseRefusesARepeatedNameByTheName(string body, string expectedName, int expectedDepth)
    {
        var result = OAuthResponseParsers.ParseTokenResponse(Respond(body), DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess, "No access token is read from the body.");

        var refused = Assert.IsInstanceOfType<OAuthRepeatedMemberName>(result.Error, "The repetition is the reason.");
        Assert.AreEqual(expectedName, refused.MemberName, "The repeated name.");
        Assert.AreEqual(expectedDepth, refused.ObjectDepth, "The depth of the object repeating it.");
        Assert.AreEqual("RFC 8259 §4", refused.Support.SpecificationReference, "The rule broken.");
        Assert.Contains(expectedName, refused.Support.Summary, "The summary names the repeated name.");
        Assert.DoesNotContain("credential-text", refused.Support.Summary, "No value the body carries is in the summary.");
        Assert.DoesNotContain("credential-text", refused.Support.LikelyCause ?? string.Empty, "No value the body carries is in the cause.");
    }


    /// <summary>
    /// RFC 8259 §8.2: an escape naming an unpaired surrogate is grammatical but names no Unicode text. A token response a member
    /// of which has a name or a string value so spelled - a parameter its success is read from, its <c>error</c>, or an
    /// extension member it reads nothing from, at the top level or nested - is refused by the first such member in document
    /// order, its name, the depth of the object carrying it and which part names no text, never answered as a response carrying
    /// no such parameter, and a parameter so spelled is never dropped from a success; the summary carries none of the values the
    /// body holds.
    /// </summary>
    /// <param name="body">The response body.</param>
    /// <param name="expectedName">The member's name as the refusal carries it.</param>
    /// <param name="expectedDepth">The depth of the object carrying the member.</param>
    /// <param name="expectedPart">Which part of the member names no Unicode text.</param>
    [TestMethod]
    [DataRow(
        /*lang=json*/ """{"access_token":"\uD800","token_type":"Bearer","refresh_token":"refresh-credential-text"}""",
        "access_token",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "An access_token naming an unpaired surrogate")]
    [DataRow(
        /*lang=json*/ """{"access_token":"access-credential-text","token_type":"\uDC00"}""",
        "token_type",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "A token_type naming an unpaired surrogate")]
    [DataRow(
        /*lang=json*/ """{"access_token":"access-credential-text","token_type":"Bearer","refresh_token":"x\uD800"}""",
        "refresh_token",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "A refresh_token naming an unpaired surrogate")]
    [DataRow(
        /*lang=json*/ """{"refresh_token":"\uD800","access_token":"\uDBFF","token_type":"Bearer"}""",
        "refresh_token",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "The first in document order, a refresh_token written ahead of the access_token")]
    [DataRow(
        /*lang=json*/ """{"error":"\uD800","access_token":"access-credential-text","token_type":"Bearer"}""",
        "error",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "An error naming an unpaired surrogate beside a success")]
    [DataRow(
        /*lang=json*/ """{"access_token":"access-credential-text","token_type":"Bearer","ext":"\uD800"}""",
        "ext",
        1,
        JsonUndecodableMemberPart.Value,
        DisplayName = "An extension member the parser reads nothing from")]
    [DataRow(
        /*lang=json*/ """{"access_token":"access-credential-text","token_type":"Bearer","ext":{"note":["\uDC00"]}}""",
        "note",
        2,
        JsonUndecodableMemberPart.Value,
        DisplayName = "A string an array holds in an extension object")]
    [DataRow(
        /*lang=json*/ """{"access_token":"access-credential-text","token_type":"Bearer","\uDC00":"x"}""",
        "\\uDC00",
        1,
        JsonUndecodableMemberPart.Name,
        DisplayName = "A member name naming an unpaired surrogate, spelled as the body escapes it")]
    public void ParseTokenResponseRefusesAnUndecodableMemberByItsName(
        string body,
        string expectedName,
        int expectedDepth,
        JsonUndecodableMemberPart expectedPart)
    {
        var result = OAuthResponseParsers.ParseTokenResponse(Respond(body), DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess, "No token is read from the body.");

        var refused = Assert.IsInstanceOfType<OAuthUndecodableMemberValue>(result.Error, "The undecodable member is the reason.");
        Assert.AreEqual(expectedName, refused.MemberName, "The member's name as it can be written.");
        Assert.AreEqual(expectedDepth, refused.ObjectDepth, "The depth of the object carrying it.");
        Assert.AreEqual(expectedPart, refused.Part, "Which part names no Unicode text.");
        Assert.AreEqual("RFC 8259 §8.2", refused.Support.SpecificationReference, "The rule broken.");
        Assert.Contains(expectedName, refused.Support.Summary, "The summary names the member.");
        Assert.DoesNotContain("credential-text", refused.Support.Summary, "No value the body carries is in the summary.");
        Assert.DoesNotContain("credential-text", refused.Support.LikelyCause ?? string.Empty, "No value the body carries is in the cause.");
    }


    /// <summary>
    /// The error a readable response names keeps its precedence over the parameters a success is read from: an error response
    /// carrying a complete success beside its error is answered as the error it names, at the token and the pushed authorization
    /// endpoints alike, and under the problem details media type as the problem it names.
    /// </summary>
    [TestMethod]
    public void TheErrorAReadableResponseNamesKeepsItsPrecedenceOverASuccess()
    {
        var token = OAuthResponseParsers.ParseTokenResponse(
            Respond(/*lang=json,strict*/ """{"error":"invalid_grant","access_token":"access-credential-text","token_type":"Bearer"}""", statusCode: 400),
            DateTimeOffset.UnixEpoch);

        var pushed = OAuthResponseParsers.ParseParResponse(
            Respond(/*lang=json,strict*/ """{"error":"invalid_request","request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":60}""", statusCode: 400));

        var problem = OAuthResponseParsers.ParseTokenResponse(
            Problem(/*lang=json,strict*/ """{"type":"invalid_grant","access_token":"access-credential-text","token_type":"Bearer"}"""),
            DateTimeOffset.UnixEpoch);

        Assert.AreEqual("invalid_grant", Assert.IsInstanceOfType<OAuthProtocolError>(token.Error).ErrorCode, "The error the token answer names.");
        Assert.AreEqual("invalid_request", Assert.IsInstanceOfType<OAuthProtocolError>(pushed.Error).ErrorCode, "The error the pushed answer names.");
        Assert.AreEqual("invalid_grant", Assert.IsInstanceOfType<OAuthProtocolError>(problem.Error).ErrorCode, "The problem the body names.");
    }


    /// <summary>
    /// An error response one of whose members names no Unicode text is no readable response, so its error has no precedence:
    /// an <c>error</c> or a problem <c>type</c> beside an <c>access_token</c> naming an unpaired surrogate is refused by the
    /// <c>access_token</c>, under the token endpoint's own media type and the problem details media type alike, though neither
    /// reads an access token.
    /// </summary>
    [TestMethod]
    public void AnErrorResponseHoldingAMemberNamingNoUnicodeTextIsRefusedByThatMember()
    {
        var error = OAuthResponseParsers.ParseTokenResponse(
            Respond(/*lang=json*/ """{"error":"invalid_grant","access_token":"\uD800"}""", statusCode: 400),
            DateTimeOffset.UnixEpoch);

        var problem = OAuthResponseParsers.ParseTokenResponse(
            Problem(/*lang=json*/ """{"type":"invalid_grant","access_token":"\uD800"}"""),
            DateTimeOffset.UnixEpoch);

        Assert.AreEqual(
            OAuthRequestParameterNames.AccessToken,
            Assert.IsInstanceOfType<OAuthUndecodableMemberValue>(error.Error).MemberName,
            "The error answer's access_token.");

        Assert.AreEqual(
            OAuthRequestParameterNames.AccessToken,
            Assert.IsInstanceOfType<OAuthUndecodableMemberValue>(problem.Error).MemberName,
            "The problem answer's access_token.");
    }


    /// <summary>
    /// A member no parser reads, holding a string naming no Unicode text, refuses every answer that holds it, as the reader's one
    /// rule judges the whole body: an answer carrying a complete token success, a complete pushed authorization success and a
    /// problem type beside an extension object whose member names no text is refused by that member at the token and the pushed
    /// authorization endpoints, under their own media type and the problem details media type, naming the member, its depth and
    /// its part and none of the values the answer holds.
    /// </summary>
    [TestMethod]
    public void AMemberNoParserReadsNamingNoUnicodeTextRefusesEveryAnswer()
    {
        var body = /*lang=json*/ """{"access_token":"access-credential-text","token_type":"Bearer","request_uri":"urn:ietf:params:oauth:request_uri:credential-text","expires_in":60,"type":"invalid_grant","ext":{"note":"\uDC00"}}""";

        OAuthParseError?[] refusals =
        [
            OAuthResponseParsers.ParseTokenResponse(Respond(body), DateTimeOffset.UnixEpoch).Error,
            OAuthResponseParsers.ParseParResponse(Respond(body)).Error,
            OAuthResponseParsers.ParseTokenResponse(Problem(body), DateTimeOffset.UnixEpoch).Error,
            OAuthResponseParsers.ParseParResponse(Problem(body)).Error
        ];

        foreach(var refusal in refusals)
        {
            var refused = Assert.IsInstanceOfType<OAuthUndecodableMemberValue>(refusal, "The extension member is the reason.");
            Assert.AreEqual("note", refused.MemberName, "The member naming no Unicode text.");
            Assert.AreEqual(2, refused.ObjectDepth, "The extension object carrying it.");
            Assert.AreEqual(JsonUndecodableMemberPart.Value, refused.Part, "Its value names no Unicode text.");
            Assert.DoesNotContain("credential-text", refused.Support.Summary, "No value the body carries is in the summary.");
        }
    }


    /// <summary>
    /// An error response's own members are read as its error is: an <c>error_description</c> or an <c>error_uri</c> carried as
    /// a string naming no Unicode text (RFC 8259 §8.2) is refused by its name, at the token and the pushed authorization
    /// endpoints alike, never answered as an error carrying no description or no location.
    /// </summary>
    /// <param name="body">The response body.</param>
    /// <param name="expectedName">The member carried as such a string.</param>
    [TestMethod]
    [DataRow(
        /*lang=json*/ """{"error":"invalid_grant","error_description":"\uD800"}""",
        "error_description",
        DisplayName = "An error_description naming an unpaired surrogate")]
    [DataRow(
        /*lang=json*/ """{"error":"invalid_grant","error_uri":"https://as.example.com/\uDC00"}""",
        "error_uri",
        DisplayName = "An error_uri naming an unpaired surrogate")]
    public void AnUndecodableMemberOfAnErrorResponseIsRefusedByItsName(string body, string expectedName)
    {
        var token = OAuthResponseParsers.ParseTokenResponse(Respond(body, statusCode: 400), DateTimeOffset.UnixEpoch);
        var pushed = OAuthResponseParsers.ParseParResponse(Respond(body, statusCode: 400));

        Assert.AreEqual(expectedName, Assert.IsInstanceOfType<OAuthUndecodableMemberValue>(token.Error).MemberName, "The token endpoint's.");
        Assert.AreEqual(expectedName, Assert.IsInstanceOfType<OAuthUndecodableMemberValue>(pushed.Error).MemberName, "The pushed authorization endpoint's.");
    }


    /// <summary>
    /// The pushed authorization response's parameters are read as the token response's are: a response repeating its
    /// <c>request_uri</c> is refused by that name (RFC 8259 §4), and a <c>request_uri</c> naming no Unicode text by its name
    /// (RFC 8259 §8.2), never answered as a response carrying no <c>request_uri</c> or as no well-formed object.
    /// </summary>
    [TestMethod]
    public void ParseParResponseRefusesARepeatedOrUndecodableRequestUriByItsName()
    {
        var repeated = OAuthResponseParsers.ParseParResponse(Respond(
            /*lang=json*/ """{"request_uri":"urn:ietf:params:oauth:request_uri:one","request_uri":"urn:ietf:params:oauth:request_uri:two","expires_in":60}"""));

        var undecodable = OAuthResponseParsers.ParseParResponse(Respond(
            /*lang=json*/ """{"request_uri":"urn:ietf:params:oauth:request_uri:\uD800","expires_in":60}"""));

        var repeatedRefusal = Assert.IsInstanceOfType<OAuthRepeatedMemberName>(repeated.Error, "The repetition is the reason.");
        Assert.AreEqual(OAuthRequestParameterNames.RequestUri, repeatedRefusal.MemberName);
        Assert.AreEqual(1, repeatedRefusal.ObjectDepth);

        var undecodableRefusal = Assert.IsInstanceOfType<OAuthUndecodableMemberValue>(undecodable.Error, "The undecodable request_uri is the reason.");
        Assert.AreEqual(OAuthRequestParameterNames.RequestUri, undecodableRefusal.MemberName);
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


    /// <summary>
    /// A problem details response states its problem through the members of the one JSON object its body is (RFC 9457
    /// section 3): a token endpoint's body under the problem details media type that is an array of problems or an object
    /// never closed states no problem, so it is refused as malformed, never read as the problem the media type names.
    /// </summary>
    /// <param name="body">The response body.</param>
    [TestMethod]
    [DataRow(
        /*lang=json,strict*/ """[{"type":"invalid_grant","detail":"an array of problems"}]""",
        DisplayName = "A token answer that is an array of problems")]
    [DataRow("{\"type\":\"invalid_grant\",\"detail\":\"never closed\"", DisplayName = "A token answer never closed")]
    public void ATokenProblemDetailsBodyThatIsNoOneObjectIsRefusedAsMalformed(string body)
    {
        var result = OAuthResponseParsers.ParseTokenResponse(
            Respond(body, statusCode: 400, contentType: WellKnownMediaTypes.Application.ProblemJson),
            DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess, "The token endpoint's answer is refused.");
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error, "The token endpoint's answer names no problem.");
    }


    /// <summary>
    /// The pushed authorization endpoint's problem details response is read as the token endpoint's is (RFC 9457 section 3,
    /// RFC 9126 section 2.3): a body under the problem details media type that is an array of problems or an object never
    /// closed is refused as malformed, never read as the problem the media type names.
    /// </summary>
    /// <param name="body">The response body.</param>
    [TestMethod]
    [DataRow(
        /*lang=json,strict*/ """[{"type":"invalid_request","detail":"an array of problems"}]""",
        DisplayName = "A pushed authorization answer that is an array of problems")]
    [DataRow(
        "{\"type\":\"invalid_request\",\"detail\":\"never closed\"",
        DisplayName = "A pushed authorization answer never closed")]
    public void APushedAuthorizationProblemDetailsBodyThatIsNoOneObjectIsRefusedAsMalformed(string body)
    {
        var result = OAuthResponseParsers.ParseParResponse(
            Respond(body, statusCode: 400, contentType: WellKnownMediaTypes.Application.ProblemJson));

        Assert.IsFalse(result.IsSuccess, "The pushed authorization endpoint's answer is refused.");
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error, "The pushed authorization endpoint's answer names no problem.");
    }


    /// <summary>
    /// A problem details response naming a member twice (RFC 8259 section 4) states no problem one way, and one carrying its
    /// <c>type</c>, <c>detail</c> or <c>instance</c> as a string naming no Unicode text (RFC 8259 section 8.2) states it in
    /// no text a client can read: each is refused by the member's name, at the token and the pushed authorization endpoints
    /// alike, never as a body that is not well-formed JSON and never read as the problem the media type names.
    /// </summary>
    [TestMethod]
    public void AProblemDetailsBodyRepeatingOrUndecodableInAMemberIsRefusedByTheName()
    {
        var repeatedBody = /*lang=json*/ """{"type":"invalid_grant","type":"invalid_client","detail":"two types"}""";
        var undecodableBody = /*lang=json*/ """{"type":"invalid_grant","detail":"\uD800"}""";

        var tokenRepeated = OAuthResponseParsers.ParseTokenResponse(Problem(repeatedBody), DateTimeOffset.UnixEpoch);
        var pushedRepeated = OAuthResponseParsers.ParseParResponse(Problem(repeatedBody));
        var tokenUndecodable = OAuthResponseParsers.ParseTokenResponse(Problem(undecodableBody), DateTimeOffset.UnixEpoch);
        var pushedUndecodable = OAuthResponseParsers.ParseParResponse(Problem(undecodableBody));

        Assert.AreEqual(
            WellKnownProblemDetailsMemberNames.Type,
            Assert.IsInstanceOfType<OAuthRepeatedMemberName>(tokenRepeated.Error).MemberName,
            "The token endpoint's answer names its type twice.");

        Assert.AreEqual(
            WellKnownProblemDetailsMemberNames.Type,
            Assert.IsInstanceOfType<OAuthRepeatedMemberName>(pushedRepeated.Error).MemberName,
            "The pushed authorization endpoint's answer names its type twice.");

        Assert.AreEqual(
            WellKnownProblemDetailsMemberNames.Detail,
            Assert.IsInstanceOfType<OAuthUndecodableMemberValue>(tokenUndecodable.Error).MemberName,
            "The token endpoint's answer carries a detail naming no Unicode text.");

        Assert.AreEqual(
            WellKnownProblemDetailsMemberNames.Detail,
            Assert.IsInstanceOfType<OAuthUndecodableMemberValue>(pushedUndecodable.Error).MemberName,
            "The pushed authorization endpoint's answer carries a detail naming no Unicode text.");
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



    /// <summary>An answer of status 400 under the problem details media type.</summary>
    /// <param name="body">The response body.</param>
    /// <returns>The response.</returns>
    private static HttpResponseData Problem(string body) =>
        Respond(body, statusCode: 400, contentType: WellKnownMediaTypes.Application.ProblemJson);


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
