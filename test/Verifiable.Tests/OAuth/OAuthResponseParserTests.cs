using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vci;
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
    /// A success Token Response granting three <c>openid_credential</c> entries, two of them for one
    /// configuration, each with two identifiers, with an entry of another type between the first two.
    /// </summary>
    private static string MultiEntryTokenResponse =>
        /*lang=json,strict*/ """{"access_token":"at","token_type":"Bearer","authorization_details":[{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential","credential_identifiers":["CivilEngineeringDegree-2023","ElectricalEngineeringDegree-2023"]},{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"123.50"}},{"type":"openid_credential","credential_configuration_id":"EmployeeBadgeCredential","credential_identifiers":["Badge-Helsinki-2024","Badge-Espoo-2024"]},{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential","credential_identifiers":["MechanicalEngineeringDegree-2024","ChemicalEngineeringDegree-2024"]}]}""";


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
    /// The <c>credential_identifiers</c> of a granted <c>openid_credential</c> entry are read with
    /// their configuration, in the order the Token Response lists them.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "credential_identifiers: REQUIRED. A non-empty array of strings, each uniquely identifying a
    /// Credential Dataset that can be issued using the Access Token returned in this response. Each of
    /// these Credential Datasets corresponds to the Credential Configuration referenced in the
    /// credential_configuration_id parameter. The Wallet MUST use these identifiers together with an
    /// Access Token in subsequent Credential Requests."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseReadsTheGrantedIdentifiersInOrder()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"at","token_type":"Bearer","authorization_details":[{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential","credential_identifiers":["CivilEngineeringDegree-2023","ElectricalEngineeringDegree-2023"]}]}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess);
        Assert.HasCount(1, result.Value.GrantedCredentialAuthorizations);
        GrantedCredentialAuthorization granted = result.Value.GrantedCredentialAuthorizations[0];
        Assert.AreEqual("UniversityDegreeCredential", granted.CredentialConfigurationId);
        Assert.AreSequenceEqual(
            ["CivilEngineeringDegree-2023", "ElectricalEngineeringDegree-2023"],
            granted.CredentialIdentifiers.ToArray());
    }


    /// <summary>
    /// A Token Response without <c>authorization_details</c> grants no <c>openid_credential</c>
    /// authorization, and the parse succeeds with an empty list.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "authorization_details: REQUIRED when the authorization_details parameter, as defined in
    /// Section 5.1.1, is used in either the Authorization Request or Token Request. OPTIONAL when
    /// scope parameter was used to request issuance of a Credential of a certain Credential
    /// Configuration."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseWithoutAuthorizationDetailsGrantsNoIdentifiers()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"at","token_type":"Bearer","scope":"UniversityDegreeCredential"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsEmpty(result.Value.GrantedCredentialAuthorizations);
    }


    /// <summary>
    /// An <c>authorization_details</c> entry whose <c>type</c> is a string other than
    /// <c>openid_credential</c> describes another API, so it is skipped and the
    /// <c>openid_credential</c> entry beside it is read.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>:
    /// "type: An identifier for the authorization details type as a string. The value of the type
    /// field determines the allowable contents of the object that contains it. The value is unique
    /// for the described API in the context of the AS. This field is REQUIRED."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseSkipsAnEntryOfAnotherType()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"at","token_type":"Bearer","authorization_details":[{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"123.50"}},{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential","credential_identifiers":["CivilEngineeringDegree-2023"]}]}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess);
        Assert.HasCount(1, result.Value.GrantedCredentialAuthorizations);
        Assert.AreEqual("UniversityDegreeCredential", result.Value.GrantedCredentialAuthorizations[0].CredentialConfigurationId);
        Assert.AreSequenceEqual(
            ["CivilEngineeringDegree-2023"],
            result.Value.GrantedCredentialAuthorizations[0].CredentialIdentifiers.ToArray());
    }


    /// <summary>
    /// Data fields of an <c>openid_credential</c> entry the reader does not recognize are ignored,
    /// and the entry's configuration and identifiers are read.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST ignore any unrecognized data fields in the authorization_details present in the
    /// Token Response."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseIgnoresUnrecognizedFieldsOfAGrantedEntry()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"at","token_type":"Bearer","authorization_details":[{"type":"openid_credential","claims":[{"path":["given_name"]}],"credential_configuration_id":"UniversityDegreeCredential","display_hint":{"locale":"en-US"},"credential_identifiers":["CivilEngineeringDegree-2023"]}]}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess);
        Assert.HasCount(1, result.Value.GrantedCredentialAuthorizations);
        Assert.AreEqual("UniversityDegreeCredential", result.Value.GrantedCredentialAuthorizations[0].CredentialConfigurationId);
        Assert.AreSequenceEqual(
            ["CivilEngineeringDegree-2023"],
            result.Value.GrantedCredentialAuthorizations[0].CredentialIdentifiers.ToArray());
    }


    /// <summary>
    /// An <c>authorization_details</c> member that is not a non-empty array of objects fails the
    /// whole parse as an invalid value of that member, so no token is surfaced.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "It is a non-empty array of objects, as defined in Section 7 of [RFC9396]."
    /// </summary>
    /// <param name="authorizationDetails">The literal member value the Token Response carries.</param>
    [TestMethod]
    [DataRow("[]")]
    [DataRow("[7]")]
    [DataRow("""{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential","credential_identifiers":["CivilEngineeringDegree-2023"]}""")]
    public void ParseTokenResponseRefusesAuthorizationDetailsThatAreNotANonEmptyArrayOfObjects(string authorizationDetails)
    {
        AssertAuthorizationDetailsAreRefused(authorizationDetails);
    }


    /// <summary>
    /// An <c>authorization_details</c> entry whose <c>type</c> is absent or not a JSON string fails
    /// the whole parse as an invalid value of the member.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>:
    /// "type: An identifier for the authorization details type as a string. The value of the type
    /// field determines the allowable contents of the object that contains it. The value is unique
    /// for the described API in the context of the AS. This field is REQUIRED."
    /// </summary>
    /// <param name="authorizationDetails">The literal member value the Token Response carries.</param>
    [TestMethod]
    [DataRow("""[{"credential_configuration_id":"UniversityDegreeCredential","credential_identifiers":["CivilEngineeringDegree-2023"]}]""")]
    [DataRow("""[{"type":7,"credential_configuration_id":"UniversityDegreeCredential","credential_identifiers":["CivilEngineeringDegree-2023"]}]""")]
    public void ParseTokenResponseRefusesAnEntryWithoutAStringType(string authorizationDetails)
    {
        AssertAuthorizationDetailsAreRefused(authorizationDetails);
    }


    /// <summary>
    /// An <c>openid_credential</c> entry without its <c>credential_configuration_id</c>, without a
    /// non-empty <c>credential_identifiers</c>, or listing an empty identifier, which names no
    /// Credential Dataset, fails the whole parse as an invalid value of the member.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.1">OID4VCI 1.0 Section 5.1.1</see>:
    /// "credential_configuration_id: REQUIRED."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "credential_identifiers: REQUIRED. A non-empty array of strings, each uniquely identifying a
    /// Credential Dataset that can be issued using the Access Token returned in this response."
    /// </summary>
    /// <param name="authorizationDetails">The literal member value the Token Response carries.</param>
    [TestMethod]
    [DataRow("""[{"type":"openid_credential","credential_identifiers":["CivilEngineeringDegree-2023"]}]""")]
    [DataRow("""[{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential"}]""")]
    [DataRow("""[{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential","credential_identifiers":[]}]""")]
    [DataRow("""[{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential","credential_identifiers":[""]}]""")]
    public void ParseTokenResponseRefusesAGrantedEntryWithoutItsRequiredMembers(string authorizationDetails)
    {
        AssertAuthorizationDetailsAreRefused(authorizationDetails);
    }


    /// <summary>
    /// A Token Response that repeats a member name is not read: one reader could select the first
    /// occurrence while another resolves the last, so the parse fails as a malformed response.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see>:
    /// "When the names within an object are not unique, the behavior of software that receives such
    /// an object is unpredictable."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusesABodyThatRepeatsAMember()
    {
        HttpResponseData response = Respond(
            """{"access_token":"at","token_type":"Bearer","access_token":"another"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess);
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
    }


    /// <summary>
    /// The access token is the <c>access_token</c> member of the response object itself: a member of
    /// that name inside a nested object, placed before the top-level one, is data of the object it
    /// stands in and is not read as the token.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>:
    /// "The parameters are serialized into a JavaScript Object Notation (JSON) structure by adding each
    /// parameter at the highest structure level."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseReadsTheTopLevelAccessTokenOverANestedOne()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"example_parameter":{"access_token":"nested-token"},"access_token":"top-level-token","token_type":"Bearer"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess, "A success response with a nested access_token member must parse.");
        Assert.AreEqual("top-level-token", result.Value.AccessToken);
    }


    /// <summary>
    /// An <c>error</c> member inside an <c>authorization_details</c> entry of another type is a data field
    /// of that entry, not the response's error parameter, so a success response carrying it parses as a
    /// success.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "The parameters are serialized into a JSON structure by adding each parameter at the highest
    /// structure level."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseReadsANestedErrorAsDataOfItsEntry()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"at","token_type":"Bearer","authorization_details":[{"type":"payment_initiation","error":"insufficient_funds"}]}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess, "An error member nested in an authorization_details entry must not make the response an error.");
        Assert.AreEqual("at", result.Value.AccessToken);
        Assert.IsEmpty(result.Value.GrantedCredentialAuthorizations);
    }


    /// <summary>
    /// A Token Response that repeats <c>expires_in</c> is refused as a malformed response before any
    /// member is read, rather than judged on the first of the two values.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see>:
    /// "When the names within an object are not unique, the behavior of software that receives such
    /// an object is unpredictable."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusesABodyThatRepeatsExpiresIn()
    {
        HttpResponseData response = Respond(
            """{"access_token":"at","token_type":"Bearer","expires_in":0,"expires_in":3600}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess);
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
    }


    /// <summary>
    /// A Token Response longer than <see cref="JwkJsonReader.MaximumDocumentLength"/>, counted in chars or
    /// in UTF-8 bytes, is refused as a malformed response whose summary names the length; it is refused
    /// before it is converted, and the refusal carries none of the body.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-9">RFC 8259 Section 9</see>:
    /// "An implementation may set limits on the size of texts that it accepts."
    /// </summary>
    /// <param name="bytesPerPaddingChar">The UTF-8 byte count of each char of the padding member's value.</param>
    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    public void ParseTokenResponseRefusesABodyOverTheDocumentLimit(int bytesPerPaddingChar)
    {
        string prefix = "{\"access_token\":\"SlAV32hkKG\",\"token_type\":\"Bearer\",\"example_parameter\":\"";
        string suffix = "\"}";
        int fixedLength = prefix.Length + suffix.Length;
        int paddingLength = (JwkJsonReader.MaximumDocumentLength + 1 - fixedLength + (bytesPerPaddingChar - 1)) / bytesPerPaddingChar;
        char paddingChar = bytesPerPaddingChar == 1 ? 'x' : (char)0xE4;
        string body = prefix + new string(paddingChar, paddingLength) + suffix;
        HttpResponseData response = Respond(body);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess, "A body over the document limit must not parse.");
        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.Contains("longer than", malformed.Support.Summary, StringComparison.Ordinal);
        Assert.IsEmpty(malformed.Body, "The refusal of an over-long body must carry none of it.");
    }


    /// <summary>
    /// The refusal of a Token Response that is not well-formed JSON, over a body holding an
    /// <c>access_token</c>, carries an empty body: the credential it holds is not preserved in the error.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.3">RFC 6749 Section 10.3</see>:
    /// "Access token credentials (as well as any confidential access token attributes) MUST be kept
    /// confidential in transit and storage, and only shared among the authorization server, the resource
    /// servers the access token is valid for, and the client to whom the access token is issued."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusalOfANotWellFormedBodyCarriesNoCredential()
    {
        HttpResponseData response = Respond(
            """{"access_token":"SlAV32hkKG","token_type":"Bearer","access_token":"SlAV32hkKG"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.DoesNotContain("SlAV32hkKG", malformed.Body, StringComparison.Ordinal);
        Assert.IsEmpty(malformed.Body, "A refused body holding an access_token must not be carried in the error.");
    }


    /// <summary>
    /// The refusal of a Token Response that carries an <c>access_token</c> without a <c>token_type</c>
    /// carries an empty body: the credential it holds is not preserved in the error.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.3">RFC 6749 Section 10.3</see>:
    /// "Access token credentials (as well as any confidential access token attributes) MUST be kept
    /// confidential in transit and storage, and only shared among the authorization server, the resource
    /// servers the access token is valid for, and the client to whom the access token is issued."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusalOfAMissingTokenTypeCarriesNoCredential()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"SlAV32hkKG","refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.Contains("token_type", malformed.Support.Summary, StringComparison.Ordinal);
        Assert.DoesNotContain("SlAV32hkKG", malformed.Body, StringComparison.Ordinal);
        Assert.IsEmpty(malformed.Body, "A refused body holding an access_token must not be carried in the error.");
    }


    /// <summary>
    /// The refusal of a Token Response whose <c>access_token</c> member is present but empty carries an
    /// empty body, so the refresh token beside it is not preserved in the error.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.4">RFC 6749 Section 10.4</see>:
    /// "Refresh tokens MUST be kept confidential in transit and storage, and shared only among the
    /// authorization server and the client to whom the refresh tokens were issued."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusalOfAnEmptyAccessTokenCarriesNoCredential()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"","token_type":"Bearer","refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.Contains("access_token", malformed.Support.Summary, StringComparison.Ordinal);
        Assert.DoesNotContain("tGzv3JOkF0XG5Qx2TlKWIA", malformed.Body, StringComparison.Ordinal);
        Assert.IsEmpty(malformed.Body, "A refused body holding an access_token member must not be carried in the error.");
    }


    /// <summary>
    /// An <c>openid_credential</c> entry whose <c>credential_configuration_id</c> is empty or white space,
    /// which names no Credential Configuration, fails the whole parse as an invalid value of the member,
    /// as an empty identifier does.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.1">OID4VCI 1.0 Section 5.1.1</see>:
    /// "credential_configuration_id: REQUIRED. String specifying a unique identifier of the Credential
    /// being described in the credential_configurations_supported map in the Credential Issuer Metadata
    /// as defined in Section 12.2.4."
    /// </summary>
    /// <param name="configurationId">The blank configuration identifier the entry carries, as JSON string content.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow(" \\t")]
    public void ParseTokenResponseRefusesABlankConfigurationIdentifier(string configurationId)
    {
        AssertAuthorizationDetailsAreRefused(
            $$"""[{"type":"openid_credential","credential_configuration_id":"{{configurationId}}","credential_identifiers":["CivilEngineeringDegree-2023"]}]""");
    }


    /// <summary>
    /// Every granted <c>openid_credential</c> entry is read, in the order the response lists them, with
    /// its complete identifier list; a configuration may be granted by more than one entry, and an entry
    /// of another type between them is skipped.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>:
    /// "An authorization_details array MAY contain multiple entries of the same type."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseReadsEveryGrantedEntryInOrder()
    {
        HttpResponseData response = Respond(MultiEntryTokenResponse);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess);
        IReadOnlyList<GrantedCredentialAuthorization> granted = result.Value.GrantedCredentialAuthorizations;
        Assert.HasCount(3, granted);
        Assert.AreEqual("UniversityDegreeCredential", granted[0].CredentialConfigurationId);
        Assert.AreSequenceEqual(["CivilEngineeringDegree-2023", "ElectricalEngineeringDegree-2023"], granted[0].CredentialIdentifiers.ToArray());
        Assert.AreEqual("EmployeeBadgeCredential", granted[1].CredentialConfigurationId);
        Assert.AreSequenceEqual(["Badge-Helsinki-2024", "Badge-Espoo-2024"], granted[1].CredentialIdentifiers.ToArray());
        Assert.AreEqual("UniversityDegreeCredential", granted[2].CredentialConfigurationId);
        Assert.AreSequenceEqual(["MechanicalEngineeringDegree-2024", "ChemicalEngineeringDegree-2024"], granted[2].CredentialIdentifiers.ToArray());
    }


    /// <summary>
    /// A configuration granted only by an entry after the first is targeted, through the parsed list, by
    /// the first identifier of that entry.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseLeadsALaterConfigurationToItsEntrysFirstIdentifier()
    {
        HttpResponseData response = Respond(MultiEntryTokenResponse);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess);
        CredentialRequestTarget? target = CredentialRequestTarget.FromGrantedAuthorizations(
            "EmployeeBadgeCredential", result.Value.GrantedCredentialAuthorizations);
        Assert.IsNotNull(target);
        Assert.AreEqual("Badge-Helsinki-2024", target.CredentialIdentifier);
        Assert.IsNull(target.CredentialConfigurationId);
    }


    /// <summary>
    /// An <c>access_token</c> whose decoded value holds a char outside <c>%x20-7E</c> (a carriage return
    /// and a line feed, a NUL, a lone surrogate) is refused as an invalid value of the member, and the
    /// refusal echoes none of the token.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.12">RFC 6749 Appendix A.12</see>:
    /// "access-token = 1*VSCHAR", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A">RFC 6749 Appendix A</see> defines
    /// "VSCHAR     = %x20-7E".
    /// </summary>
    /// <param name="accessToken">The <c>access_token</c> member's value, as JSON string content.</param>
    [TestMethod]
    [DataRow("SlAV32hkKG\\r\\nX-Injected: yes")]
    [DataRow("SlAV32hkKG\\u0000")]
    [DataRow("SlAV32hkKG\\ud800")]
    public void ParseTokenResponseRefusesAnAccessTokenOutsideItsGrammar(string accessToken)
    {
        HttpResponseData response = Respond(
            $$"""{"access_token":"{{accessToken}}","token_type":"Bearer"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        _ = AssertRefusedWithoutItsValue(result, "access_token", "SlAV32hkKG");
    }


    /// <summary>
    /// A <c>refresh_token</c> whose decoded value holds a line feed is refused as an invalid value of the
    /// member, and the refusal echoes neither the refresh token nor the access token beside it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.17">RFC 6749 Appendix A.17</see>:
    /// "refresh-token = 1*VSCHAR", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A">RFC 6749 Appendix A</see> defines
    /// "VSCHAR     = %x20-7E".
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusesARefreshTokenOutsideItsGrammar()
    {
        HttpResponseData response = Respond(
            """{"access_token":"SlAV32hkKG","token_type":"Bearer","refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA\n"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthInvalidFieldValue invalid = AssertRefusedWithoutItsValue(result, "refresh_token", "tGzv3JOkF0XG5Qx2TlKWIA");
        Assert.DoesNotContain("SlAV32hkKG", invalid.ToString(), StringComparison.Ordinal);
    }


    /// <summary>
    /// A <c>token_type</c> holding a space, which neither a type name nor a URI-reference holds, is refused
    /// as an invalid value of the member, and the refusal echoes none of the access token beside it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", "type-name  = 1*name-char" and
    /// "name-char  = "-" / "." / "_" / DIGIT / ALPHA".
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusesATokenTypeOutsideItsGrammar()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"SlAV32hkKG","token_type":"Bearer Token"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthInvalidFieldValue invalid = AssertRefusedWithoutItsValue(result, "token_type", "Bearer Token");
        Assert.DoesNotContain("SlAV32hkKG", invalid.ToString(), StringComparison.Ordinal);
    }


    /// <summary>
    /// The refusal of a JSON-shaped Token Response that holds a refresh token and no access token carries
    /// an empty body: the refresh token it holds is not preserved in the error.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.4">RFC 6749 Section 10.4</see>:
    /// "Refresh tokens MUST be kept confidential in transit and storage, and shared only among the
    /// authorization server and the client to whom the refresh tokens were issued."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusalOfARefreshTokenOnlyBodyCarriesNoCredential()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"token_type":"Bearer","refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA","expires_in":3600}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.Contains("access_token", malformed.Support.Summary, StringComparison.Ordinal);
        Assert.DoesNotContain("tGzv3JOkF0XG5Qx2TlKWIA", malformed.Body, StringComparison.Ordinal);
        Assert.IsEmpty(malformed.Body, "A refused JSON-shaped body must not be carried in the error.");
    }


    /// <summary>
    /// The refusal of a JSON Token Response that holds an ID Token and no access token carries an empty
    /// body. The library's rule: no member of a refused body that is not an HTML or XML document is
    /// carried in the error, since the body is refused before it is known which of its members are
    /// credentials; the same body may hold an access token, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.3">RFC 6749 Section 10.3</see> holds
    /// confidential: "Access token credentials (as well as any confidential access token attributes) MUST
    /// be kept confidential in transit and storage, and only shared among the authorization server, the
    /// resource servers the access token is valid for, and the client to whom the access token is
    /// issued." No clause of RFC 6749 or OpenID Connect Core 1.0 on disk states an ID Token's
    /// confidentiality in a Token Response.
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusalOfAnIdTokenOnlyBodyCarriesNoCredential()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"token_type":"Bearer","id_token":"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIyNDgyODk3NjEwMDEifQ.c2lnbmF0dXJl"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.Contains("access_token", malformed.Support.Summary, StringComparison.Ordinal);
        Assert.DoesNotContain("eyJzdWIiOiIyNDgyODk3NjEwMDEifQ", malformed.Body, StringComparison.Ordinal);
        Assert.IsEmpty(malformed.Body, "A refused JSON-shaped body must not be carried in the error.");
    }


    /// <summary>
    /// The refusal of a truncated Token Response, JSON-shaped but not well-formed, that holds a refresh
    /// token carries an empty body: the refresh token it holds is not preserved in the error.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.4">RFC 6749 Section 10.4</see>:
    /// "Refresh tokens MUST be kept confidential in transit and storage, and shared only among the
    /// authorization server and the client to whom the refresh tokens were issued."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusalOfATruncatedBodyHoldingARefreshTokenCarriesNoCredential()
    {
        HttpResponseData response = Respond(
            """{"token_type":"Bearer","refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA","acc""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.Contains("not well-formed", malformed.Support.Summary, StringComparison.Ordinal);
        Assert.DoesNotContain("tGzv3JOkF0XG5Qx2TlKWIA", malformed.Body, StringComparison.Ordinal);
        Assert.IsEmpty(malformed.Body, "A refused JSON-shaped body must not be carried in the error.");
    }


    /// <summary>
    /// The refusal of a Token Response whose <c>access_token</c> member name is spelled with JSON escapes
    /// carries an empty body: the token it holds is not preserved in the error.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.3">RFC 6749 Section 10.3</see>:
    /// "Access token credentials (as well as any confidential access token attributes) MUST be kept
    /// confidential in transit and storage, and only shared among the authorization server, the resource
    /// servers the access token is valid for, and the client to whom the access token is issued."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusalOfAnEscapedAccessTokenNameCarriesNoCredential()
    {
        HttpResponseData response = Respond(
            """{"\u0061ccess\u005ftoken":"SlAV32hkKG","token_type":"Bearer"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.DoesNotContain("SlAV32hkKG", malformed.Body, StringComparison.Ordinal);
        Assert.IsEmpty(malformed.Body, "A refused JSON-shaped body must not be carried in the error.");
    }


    /// <summary>
    /// The refusal of a malformed <c>authorization_details</c> member whose entry carries a copy of the
    /// token under a member named <c>access_token</c> names the member and its reason and echoes none of
    /// the member's text.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.3">RFC 6749 Section 10.3</see>:
    /// "Access token credentials (as well as any confidential access token attributes) MUST be kept
    /// confidential in transit and storage, and only shared among the authorization server, the resource
    /// servers the access token is valid for, and the client to whom the access token is issued."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusalOfAuthorizationDetailsCarriesNoCredential()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"SlAV32hkKG","token_type":"Bearer","authorization_details":[{"type":"openid_credential","credential_configuration_id":"","credential_identifiers":["CivilEngineeringDegree-2023"],"access_token":"SlAV32hkKG"}]}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthInvalidFieldValue invalid = Assert.IsInstanceOfType<OAuthInvalidFieldValue>(result.Error);
        Assert.AreEqual("authorization_details", invalid.FieldName);
        Assert.DoesNotContain("SlAV32hkKG", invalid.ReceivedValue, StringComparison.Ordinal);
        Assert.IsEmpty(invalid.ReceivedValue, "A refused authorization_details member must not be echoed in the error.");
        Assert.DoesNotContain("SlAV32hkKG", invalid.ToString(), StringComparison.Ordinal);
    }


    /// <summary>
    /// The refusal of a token endpoint body that is not JSON-shaped, an HTML error page, keeps the body
    /// for diagnostics: it holds no Token Response parameter.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>:
    /// "The parameters are included in the entity-body of the HTTP response using the "application/json"
    /// media type as defined by [RFC4627]."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusalOfAnHtmlBodyKeepsItsBody()
    {
        const string HtmlBody = "<html><body><h1>502 Bad Gateway</h1></body></html>";
        HttpResponseData response = Respond(HtmlBody, statusCode: 502);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.AreEqual(HtmlBody, malformed.Body, "A refused body that is not JSON-shaped must be kept for diagnostics.");
    }


    /// <summary>
    /// An <c>error</c> value holding a line feed, outside the characters Section 5.2 permits, makes the
    /// response malformed rather than a protocol error carrying that code.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B /
    /// %x5D-7E."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusesAnErrorCodeOutsideItsCharacterSet()
    {
        HttpResponseData response = Respond(
            """{"error":"invalid_grant\nX-Injected: yes"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess);
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
    }


    /// <summary>
    /// An <c>error_description</c> holding a line feed, outside the characters Section 5.2 permits, is
    /// read as absent: the protocol error stands with its code and carries no description.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error_description" parameter MUST NOT include characters outside the set %x20-21 /
    /// %x23-5B / %x5D-7E."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseReadsAnErrorDescriptionOutsideItsCharacterSetAsAbsent()
    {
        HttpResponseData response = Respond(
            """{"error":"invalid_grant","error_description":"line one\nline two"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", protocolError.ErrorCode);
        Assert.IsNull(protocolError.ErrorDescription, "A description outside the Section 5.2 character set must be read as absent.");
        Assert.DoesNotContain("line one", protocolError.Support.Summary, StringComparison.Ordinal);
    }


    /// <summary>
    /// An <c>error_uri</c> holding a line feed, outside the characters Section 5.2 permits, is read as
    /// absent: the protocol error stands with its code and carries no URI.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error_uri" parameter MUST conform to the URI-reference syntax and thus MUST NOT
    /// include characters outside the set %x21 / %x23-5B / %x5D-7E."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseReadsAnErrorUriOutsideItsCharacterSetAsAbsent()
    {
        HttpResponseData response = Respond(
            """{"error":"invalid_grant","error_uri":"https://as.example.com/err\nors"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", protocolError.ErrorCode);
        Assert.IsNull(protocolError.ErrorUri, "An error_uri outside the Section 5.2 character set must be read as absent.");
    }


    /// <summary>
    /// A token endpoint error response that repeats a member is not read as a protocol error: the body is
    /// refused as malformed before any member is read, as every Token Response body is.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see>:
    /// "When the names within an object are not unique, the behavior of software that receives such
    /// an object is unpredictable."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusesAnErrorBodyThatRepeatsAMember()
    {
        HttpResponseData response = Respond(
            """{"error":"invalid_grant","error":"invalid_grant"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess);
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
    }


    /// <summary>
    /// The refusal of a token endpoint body that is not an HTML or XML document (a form-encoded body, a
    /// JSON string root, a plain-text body, a body of digits) carries an empty body, and the error's
    /// string form holds none of the token the body names: a refused body is kept only when its first
    /// char is <c>&lt;</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.3">RFC 6749 Section 10.3</see>:
    /// "Access token credentials (as well as any confidential access token attributes) MUST be kept
    /// confidential in transit and storage, and only shared among the authorization server, the resource
    /// servers the access token is valid for, and the client to whom the access token is issued."
    /// </summary>
    /// <param name="body">The token endpoint's body.</param>
    /// <param name="token">The token the body names, which the error must not hold.</param>
    [TestMethod]
    [DataRow("access_token=SlAV32hkKG&token_type=bearer&expires_in=3600", "SlAV32hkKG")]
    [DataRow("\"SlAV32hkKG\"", "SlAV32hkKG")]
    [DataRow("invalid token SlAV32hkKG", "SlAV32hkKG")]
    [DataRow("12345", "12345")]
    public void ParseTokenResponseRefusalOfABodyThatIsNotHtmlOrXmlCarriesNoBody(string body, string token)
    {
        HttpResponseData response = Respond(body);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess, "A body that is not a Token Response must not parse.");
        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.IsEmpty(malformed.Body, "A refused body that is not an HTML or XML document must not be carried in the error.");
        Assert.DoesNotContain(token, malformed.ToString(), StringComparison.Ordinal);
    }


    /// <summary>
    /// The refusal of a JSON object that holds an <c>access_token</c> behind a byte order mark carries an
    /// empty body, and the error's string form holds none of the token: the mark is stripped before the
    /// first char is tested, and that char is not <c>&lt;</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.3">RFC 6749 Section 10.3</see>:
    /// "Access token credentials (as well as any confidential access token attributes) MUST be kept
    /// confidential in transit and storage, and only shared among the authorization server, the resource
    /// servers the access token is valid for, and the client to whom the access token is issued."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 Section 8.1</see>:
    /// "Implementations MUST NOT add a byte order mark (U+FEFF) to the beginning of a
    /// networked-transmitted JSON text."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusalOfAByteOrderMarkedJsonObjectCarriesNoBody()
    {
        HttpResponseData response = Respond(
            "\uFEFF" + """{"access_token":"SlAV32hkKG","token_type":"Bearer"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.IsEmpty(malformed.Body, "A refused body behind a byte order mark must not be carried in the error.");
        Assert.DoesNotContain("SlAV32hkKG", malformed.ToString(), StringComparison.Ordinal);
    }


    /// <summary>
    /// A <c>token_type</c> written as an RFC 3986 URI-reference (a URI behind its scheme, whatever its
    /// authority's port, or a relative reference whose first segment holds no colon) is accepted and
    /// surfaced as written.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.1">RFC 3986 Section 4.1</see> defines
    /// "URI-reference = URI / relative-ref".
    /// </summary>
    /// <param name="tokenType">The <c>token_type</c> the Token Response carries.</param>
    [TestMethod]
    [DataRow("urn:ietf:params:oauth:token-type:jwt")]
    [DataRow("https://as.example/types/bearer")]
    [DataRow("a:b")]
    [DataRow("a:b:c")]
    [DataRow("https://as.example:99999/t")]
    [DataRow("http://")]
    [DataRow("types/bearer")]
    public void ParseTokenResponseAcceptsAUriReferenceTokenType(string tokenType)
    {
        HttpResponseData response = Respond(
            $$"""{"access_token":"SlAV32hkKG","token_type":"{{tokenType}}"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess, "A URI-reference token_type must be accepted.");
        Assert.AreEqual(tokenType, result.Value.TokenType);
    }


    /// <summary>
    /// A present <c>refresh_token</c> whose value is empty is refused as an invalid value of the member,
    /// and the refusal echoes none of the access token beside it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.17">RFC 6749 Appendix A.17</see>:
    /// "refresh-token = 1*VSCHAR".
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusesAPresentEmptyRefreshToken()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"SlAV32hkKG","token_type":"Bearer","refresh_token":""}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        _ = AssertRefusedWithoutItsValue(result, "refresh_token", "SlAV32hkKG");
    }


    /// <summary>
    /// A <c>scope</c> whose decoded value holds a carriage return and a line feed, outside the scope
    /// grammar, is refused as an invalid value of the member, and the refusal echoes neither the scope nor
    /// the access token beside it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.4">RFC 6749 Appendix A.4</see>:
    /// "scope       = scope-token *( SP scope-token )" and "scope-token = 1*NQCHAR", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A">RFC 6749 Appendix A</see> defines
    /// "NQCHAR     = %x21 / %x23-5B / %x5D-7E".
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusesAScopeOutsideItsGrammar()
    {
        HttpResponseData response = Respond(
            """{"access_token":"SlAV32hkKG","token_type":"Bearer","scope":"openid\r\nX-Injected: yes"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthInvalidFieldValue invalid = AssertRefusedWithoutItsValue(result, "scope", "X-Injected");
        Assert.DoesNotContain("SlAV32hkKG", invalid.ToString(), StringComparison.Ordinal);
    }


    /// <summary>
    /// An <c>error</c> value holding a quotation mark, outside the characters Section 5.2 permits, makes
    /// the response malformed rather than a protocol error carrying that code.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B /
    /// %x5D-7E."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseRefusesAnErrorCodeHoldingAQuotationMark()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"error":"bad\"code"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess);
        _ = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
    }


    /// <summary>
    /// An <c>error_description</c> holding a reverse solidus, outside the characters Section 5.2 permits,
    /// is read as absent: the protocol error stands with its code and carries no description.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error_description" parameter MUST NOT include characters outside the set %x20-21 /
    /// %x23-5B / %x5D-7E."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseReadsAnErrorDescriptionHoldingAReverseSolidusAsAbsent()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"error":"invalid_grant","error_description":"grant at C:\\grants rejected"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", protocolError.ErrorCode);
        Assert.IsNull(protocolError.ErrorDescription, "A description holding a reverse solidus must be read as absent.");
    }


    /// <summary>
    /// An <c>error_uri</c> holding a space, outside the characters Section 5.2 permits for it, is read as
    /// absent: the protocol error stands with its code and carries no URI.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error_uri" parameter MUST conform to the URI-reference syntax and thus MUST NOT
    /// include characters outside the set %x21 / %x23-5B / %x5D-7E."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseReadsAnErrorUriHoldingASpaceAsAbsent()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"error":"invalid_grant","error_uri":"https://as.example/a b"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", protocolError.ErrorCode);
        Assert.IsNull(protocolError.ErrorUri, "An error_uri holding a space must be read as absent.");
    }


    /// <summary>
    /// An <c>error</c> member whose value is empty, with or without a token beside it, is no error code:
    /// the response is malformed, and the refused JSON body is not carried in the error.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.7">RFC 6749 Appendix A.7</see>:
    /// "error             = 1*NQSCHAR".
    /// </summary>
    /// <param name="body">The token endpoint's body.</param>
    [TestMethod]
    [DataRow("""{"error":""}""")]
    [DataRow("""{"error":"","access_token":"SlAV32hkKG","token_type":"Bearer"}""")]
    public void ParseTokenResponseRefusesAnEmptyErrorCode(string body)
    {
        HttpResponseData response = Respond(body, statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess, "An empty error code must fail the parse.");
        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.IsEmpty(malformed.Body, "A refused JSON body must not be carried in the error.");
        Assert.DoesNotContain("SlAV32hkKG", malformed.ToString(), StringComparison.Ordinal);
    }


    /// <summary>
    /// An <c>error_uri</c> that is not an absolute URI of the <c>https</c> or <c>http</c> scheme (another
    /// scheme, a relative reference, an empty value) identifies no web page: it is read as absent and the
    /// protocol error stands with its code.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "error_uri OPTIONAL. A URI identifying a human-readable web page with information about the
    /// error, used to provide the client developer with additional information about the error."
    /// </summary>
    /// <param name="errorUri">The <c>error_uri</c> the error response carries.</param>
    [TestMethod]
    [DataRow("javascript:alert(1)")]
    [DataRow("file:///etc/passwd")]
    [DataRow("data:text/html,x")]
    [DataRow("errors/invalid_grant")]
    [DataRow("")]
    public void ParseTokenResponseReadsAnErrorUriThatNamesNoWebPageAsAbsent(string errorUri)
    {
        HttpResponseData response = Respond(
            $$"""{"error":"invalid_grant","error_uri":"{{errorUri}}"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", protocolError.ErrorCode);
        Assert.IsNull(protocolError.ErrorUri, "An error_uri that names no web page must be read as absent.");
    }


    /// <summary>
    /// An <c>error_uri</c> of the <c>https</c> or <c>http</c> scheme that does not conform to the
    /// URI-reference syntax (a char no URI-reference holds, a <c>%</c> not followed by two hex digits, a
    /// second <c>#</c>) is read as absent and the protocol error stands with its code.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error_uri" parameter MUST conform to the URI-reference syntax and thus MUST NOT
    /// include characters outside the set %x21 / %x23-5B / %x5D-7E."
    /// </summary>
    /// <param name="errorUri">The <c>error_uri</c> the error response carries.</param>
    [TestMethod]
    [DataRow("https://as.example/<script>")]
    [DataRow("https://as.example/a{b}")]
    [DataRow("https://as.example/a|b")]
    [DataRow("https://as.example/a^b")]
    [DataRow("https://as.example/a`b")]
    [DataRow("https://as.example/%zz")]
    [DataRow("https://a/b#c#d")]
    public void ParseTokenResponseReadsAnErrorUriOutsideTheUriReferenceSyntaxAsAbsent(string errorUri)
    {
        HttpResponseData response = Respond(
            $$"""{"error":"invalid_grant","error_uri":"{{errorUri}}"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", protocolError.ErrorCode);
        Assert.IsNull(protocolError.ErrorUri, "An error_uri outside the URI-reference syntax must be read as absent.");
    }


    /// <summary>
    /// An <c>https</c> or <c>http</c> <c>error_uri</c> whose authority carries userinfo is read as absent
    /// and the protocol error stands with its code.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">RFC 9110 Section 4.2.4</see>:
    /// "Before making use of an "http" or "https" URI reference received from an untrusted source, a
    /// recipient SHOULD parse for userinfo and treat its presence as an error; it is likely being used to
    /// obscure the authority for the sake of phishing attacks."
    /// </summary>
    /// <param name="errorUri">The <c>error_uri</c> the error response carries.</param>
    [TestMethod]
    [DataRow("https://as.example@evil.example/")]
    [DataRow("https://user:pw@as.example/e")]
    [DataRow("https://user@as.example/e")]
    public void ParseTokenResponseReadsAnErrorUriWithUserinfoAsAbsent(string errorUri)
    {
        HttpResponseData response = Respond(
            $$"""{"error":"invalid_grant","error_uri":"{{errorUri}}"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", protocolError.ErrorCode);
        Assert.IsNull(protocolError.ErrorUri, "An error_uri carrying userinfo must be read as absent.");
    }


    /// <summary>
    /// An <c>https</c> or <c>http</c> <c>error_uri</c> whose hier-part does not start with <c>//</c>, or
    /// whose authority is empty, names no origin server: it is read as absent and the protocol error
    /// stands with its code. A row whose value is also refused as an absolute URI where the protocol
    /// error is built is a pin of the rule.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.2">RFC 9110 Section 4.2.2</see>:
    /// "https-URI = "https" "://" authority path-abempty [ "?" query ]" and "A sender MUST NOT generate an
    /// "https" URI with an empty host identifier.  A recipient that processes such a URI reference MUST
    /// reject it as invalid."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.1">RFC 9110 Section 4.2.1</see>:
    /// "http-URI = "http" "://" authority path-abempty [ "?" query ]".
    /// </summary>
    /// <param name="errorUri">The <c>error_uri</c> the error response carries.</param>
    [TestMethod]
    [DataRow("https:")]
    [DataRow("https:x")]
    [DataRow("https:/as.example@evil.example/")]
    [DataRow("https:as.example@evil.example")]
    [DataRow("http:/user@evil.example")]
    public void ParseTokenResponseReadsAnErrorUriWithoutAnAuthorityAsAbsent(string errorUri)
    {
        HttpResponseData response = Respond(
            $$"""{"error":"invalid_grant","error_uri":"{{errorUri}}"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", protocolError.ErrorCode);
        Assert.IsNull(protocolError.ErrorUri, "An error_uri without a non-empty authority must be read as absent.");
    }


    /// <summary>
    /// An <c>https</c> <c>error_uri</c> whose host is empty (an empty authority, an empty host before a
    /// path, a port or an empty port, an empty bracketed host with or without a port) is read as absent
    /// and the protocol error stands with its code. A row whose value is also refused as an absolute URI
    /// where the protocol error is built is a pin of the rule.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.2">RFC 9110 Section 4.2.2</see>:
    /// "A sender MUST NOT generate an "https" URI with an empty host identifier.  A recipient that
    /// processes such a URI reference MUST reject it as invalid."
    /// </summary>
    /// <param name="errorUri">The <c>error_uri</c> the error response carries.</param>
    [TestMethod]
    [DataRow("https://")]
    [DataRow("https:///as.example@evil.example/")]
    [DataRow("https://:8443/e")]
    [DataRow("https://:/e")]
    [DataRow("https://[]/e")]
    [DataRow("https://[]:8443/e")]
    public void ParseTokenResponseReadsAnErrorUriWithAnEmptyHostAsAbsent(string errorUri)
    {
        HttpResponseData response = Respond(
            $$"""{"error":"invalid_grant","error_uri":"{{errorUri}}"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", protocolError.ErrorCode);
        Assert.IsNull(protocolError.ErrorUri, "An error_uri with an empty host must be read as absent.");
    }


    /// <summary>
    /// An <c>https</c> <c>error_uri</c> whose authority is not a non-empty host with an optional port of
    /// digits (a bracketed host followed by more than a port, a port holding a letter, a bracket that
    /// never closes, a host holding a <c>:</c>, a bracketed host that is no IPv6 address, an IPvFuture
    /// literal, a zone identifier) is read as absent and the protocol error stands with its code. A row
    /// whose value is also refused as an absolute URI where the protocol error is built is a pin of the
    /// rule.
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2">RFC 3986 Section 3.2</see>:
    /// "authority   = [ userinfo "@" ] host [ ":" port ]".
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2">RFC 3986 Section 3.2.2</see>:
    /// "IP-literal = "[" ( IPv6address / IPvFuture  ) "]"" and
    /// "reg-name    = *( unreserved / pct-encoded / sub-delims )".
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.3">RFC 3986 Section 3.2.3</see>:
    /// "port        = *DIGIT".
    /// </summary>
    /// <param name="errorUri">The <c>error_uri</c> the error response carries.</param>
    [TestMethod]
    [DataRow("https://[::1]evil.example/")]
    [DataRow("https://as.example:8x/")]
    [DataRow("https://[::1/")]
    [DataRow("https://a:b:80/e")]
    [DataRow("https://[x]/e")]
    [DataRow("https://[:]/e")]
    [DataRow("https://[a[b]/e")]
    [DataRow("https://[v1.x]/e")]
    [DataRow("https://[fe80::1%25eth0]/e")]
    [DataRow("https://[1.2.3.4]/e")]
    public void ParseTokenResponseReadsAnErrorUriWhoseAuthorityIsNoHostAndPortAsAbsent(string errorUri)
    {
        HttpResponseData response = Respond(
            $$"""{"error":"invalid_grant","error_uri":"{{errorUri}}"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", protocolError.ErrorCode);
        Assert.IsNull(protocolError.ErrorUri, "An error_uri whose authority is no host and port must be read as absent.");
    }


    /// <summary>
    /// An <c>https</c> <c>error_uri</c> whose authority is a host with an optional port (a bracketed
    /// IP-literal holding an IPv6 address with or without a port, a registered name with a port or with
    /// an empty port) is surfaced as written.
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2">RFC 3986 Section 3.2</see>:
    /// "authority   = [ userinfo "@" ] host [ ":" port ]".
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2">RFC 3986 Section 3.2.2</see>:
    /// "IP-literal = "[" ( IPv6address / IPvFuture  ) "]"".
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.3">RFC 3986 Section 3.2.3</see>:
    /// "port        = *DIGIT".
    /// </summary>
    /// <param name="errorUri">The <c>error_uri</c> the error response carries.</param>
    [TestMethod]
    [DataRow("https://[::1]/e")]
    [DataRow("https://[::1]:8443/e")]
    [DataRow("https://[2001:db8::1]:8443/e")]
    [DataRow("https://as.example:8443/e")]
    [DataRow("https://as.example:/e")]
    public void ParseTokenResponseSurfacesAnErrorUriWithAHostAndPortAsWritten(string errorUri)
    {
        HttpResponseData response = Respond(
            $$"""{"error":"invalid_grant","error_uri":"{{errorUri}}"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.IsNotNull(protocolError.ErrorUri, "An https error_uri whose authority is a host and port must be surfaced.");
        Assert.AreEqual(errorUri, protocolError.ErrorUri.OriginalString);
    }


    /// <summary>
    /// An <c>https</c> <c>error_uri</c> that holds an <c>@</c> after its authority, in the path or the
    /// query, is surfaced as written: the authority ends at the first <c>/</c>, <c>?</c> or <c>#</c>, so
    /// that <c>@</c> carries no userinfo.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">RFC 9110 Section 4.2.4</see>:
    /// "Before making use of an "http" or "https" URI reference received from an untrusted source, a
    /// recipient SHOULD parse for userinfo and treat its presence as an error; it is likely being used to
    /// obscure the authority for the sake of phishing attacks."
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2">RFC 3986 Section 3.2</see>:
    /// "authority   = [ userinfo "@" ] host [ ":" port ]".
    /// </summary>
    /// <param name="errorUri">The <c>error_uri</c> the error response carries.</param>
    [TestMethod]
    [DataRow("https://as.example/path@x")]
    [DataRow("https://as.example?x=@")]
    public void ParseTokenResponseSurfacesAnErrorUriWithAnAtSignAfterItsAuthorityAsWritten(string errorUri)
    {
        HttpResponseData response = Respond(
            $$"""{"error":"invalid_grant","error_uri":"{{errorUri}}"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.IsNotNull(protocolError.ErrorUri, "An https error_uri whose @ follows its authority must be surfaced.");
        Assert.AreEqual(errorUri, protocolError.ErrorUri.OriginalString);
    }


    /// <summary>
    /// An <c>error_uri</c> that is a URI of the <c>https</c> or <c>http</c> scheme, the scheme compared
    /// without case, with a query or a fragment or neither, is surfaced as written.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "error_uri OPTIONAL. A URI identifying a human-readable web page with information about the
    /// error, used to provide the client developer with additional information about the error."
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3">RFC 3986 Section 3</see>:
    /// "URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]".
    /// </summary>
    /// <param name="errorUri">The <c>error_uri</c> the error response carries.</param>
    [TestMethod]
    [DataRow("https://as.example/err")]
    [DataRow("HTTP://as.example/err")]
    [DataRow("http://as.example/e#frag")]
    [DataRow("https://as.example/e?q=1")]
    [DataRow("HTTPS://as.example/e")]
    public void ParseTokenResponseSurfacesAWebPageErrorUriAsWritten(string errorUri)
    {
        HttpResponseData response = Respond(
            $$"""{"error":"invalid_grant","error_uri":"{{errorUri}}"}""",
            statusCode: 400);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.IsNotNull(protocolError.ErrorUri, "An http or https error_uri must be surfaced.");
        Assert.AreEqual(errorUri, protocolError.ErrorUri.OriginalString);
    }


    /// <summary>
    /// A present <c>id_token</c> that is empty or holds a char outside the JWS Compact Serialization's
    /// alphabet (a carriage return and a line feed, a NUL, a <c>+</c>, a space) is refused as an invalid
    /// value of the member, and the refusal echoes none of it or of the access token beside it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-7.1">RFC 7515 Section 7.1</see>:
    /// "The JWS Compact Serialization represents digitally signed or MACed content as a compact, URL-safe
    /// string. This string is: BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) ||
    /// '.' || BASE64URL(JWS Signature)".
    /// </summary>
    /// <param name="idToken">The <c>id_token</c> the Token Response carries, as JSON string content.</param>
    [TestMethod]
    [DataRow("eyJhbGciOiJub25lIn0.e30.\\r\\nX-Injected: yes")]
    [DataRow("eyJhbGciOiJub25lIn0.e30.\\u0000")]
    [DataRow("eyJhbGciOiJub25lIn0+.e30.")]
    [DataRow("eyJhbGciOiJub25lIn0 .e30.")]
    [DataRow("")]
    public void ParseTokenResponseRefusesAnIdTokenOutsideTheCompactSerialization(string idToken)
    {
        HttpResponseData response = Respond(
            $$"""{"access_token":"SlAV32hkKG","token_type":"Bearer","id_token":"{{idToken}}"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthInvalidFieldValue invalid = AssertRefusedWithoutItsValue(result, "id_token", "SlAV32hkKG");
        Assert.DoesNotContain("eyJhbGciOiJub25lIn0", invalid.ToString(), StringComparison.Ordinal);
    }


    /// <summary>
    /// A present <c>id_token</c> of base64url chars and periods is surfaced as written.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-7.1">RFC 7515 Section 7.1</see>:
    /// "The JWS Compact Serialization represents digitally signed or MACed content as a compact, URL-safe
    /// string."
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseSurfacesACompactSerializationIdTokenAsWritten()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"SlAV32hkKG","token_type":"Bearer","id_token":"eyJhbGciOiJub25lIn0.e30."}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess, "An id_token in the compact serialization alphabet must be accepted.");
        Assert.AreEqual("eyJhbGciOiJub25lIn0.e30.", result.Value.IdToken);
    }


    /// <summary>
    /// A <c>token_type</c> that is neither a type name nor an RFC 3986 URI-reference (a quotation mark, a
    /// reverse solidus, a brace or a bracket outside an authority, a percent sign without two hex digits,
    /// a second number sign, or a first segment holding a colon behind no scheme) is refused as an invalid
    /// value of the member with an empty received value.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">RFC 3986 Section 4.2</see> holds:
    /// "A path segment that contains a colon character (e.g., "this:that") cannot be used as the first
    /// segment of a relative-path reference, as it would be mistaken for a scheme name."
    /// </summary>
    /// <param name="tokenType">The <c>token_type</c> the Token Response carries, as JSON string content.</param>
    [TestMethod]
    [DataRow("a\\\"b")]
    [DataRow("a\\\\b")]
    [DataRow("a%zz")]
    [DataRow("%")]
    [DataRow("a#b#c")]
    [DataRow("::")]
    [DataRow("1:x")]
    [DataRow(":a")]
    [DataRow("C:\\\\x")]
    [DataRow("\\\\\\\\server\\\\share")]
    [DataRow("a{b}")]
    [DataRow("[a]")]
    public void ParseTokenResponseRefusesATokenTypeOutsideTheUriReferenceGrammar(string tokenType)
    {
        HttpResponseData response = Respond(
            $$"""{"access_token":"SlAV32hkKG","token_type":"{{tokenType}}"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        _ = AssertRefusedWithoutItsValue(result, "token_type", "SlAV32hkKG");
    }


    /// <summary>
    /// A present <c>scope</c> outside Appendix A.4 (a leading, trailing or doubled space, a quotation mark,
    /// a reverse solidus, an empty value) is refused as an invalid value of the member with an empty
    /// received value.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.4">RFC 6749 Appendix A.4</see>:
    /// "scope       = scope-token *( SP scope-token )" and "scope-token = 1*NQCHAR", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A">RFC 6749 Appendix A</see> defines
    /// "NQCHAR     = %x21 / %x23-5B / %x5D-7E".
    /// </summary>
    /// <param name="scope">The <c>scope</c> the Token Response carries, as JSON string content.</param>
    [TestMethod]
    [DataRow(" openid")]
    [DataRow("openid ")]
    [DataRow("openid  profile")]
    [DataRow("open\\\"id")]
    [DataRow("open\\\\id")]
    [DataRow("")]
    public void ParseTokenResponseRefusesAScopeOutsideAppendixA4(string scope)
    {
        HttpResponseData response = Respond(
            $$"""{"access_token":"SlAV32hkKG","token_type":"Bearer","scope":"{{scope}}"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        _ = AssertRefusedWithoutItsValue(result, "scope", "SlAV32hkKG");
    }


    /// <summary>
    /// A present <c>scope</c> of two scope tokens separated by one space is surfaced as written.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.4">RFC 6749 Appendix A.4</see>:
    /// "scope       = scope-token *( SP scope-token )" and "scope-token = 1*NQCHAR".
    /// </summary>
    [TestMethod]
    public void ParseTokenResponseSurfacesAScopeOfTwoScopeTokens()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"access_token":"SlAV32hkKG","token_type":"Bearer","scope":"openid profile"}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsTrue(result.IsSuccess, "A scope within Appendix A.4 must be accepted.");
        Assert.AreEqual("openid profile", result.Value.Scope);
    }


    /// <summary>
    /// The refusal of an HTML document behind a byte order mark, alone or followed by white space, keeps
    /// the body: the mark and the white space are stripped before the first char is tested, and that char
    /// is <c>&lt;</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 Section 8.1</see>:
    /// "Implementations MUST NOT add a byte order mark (U+FEFF) to the beginning of a
    /// networked-transmitted JSON text."
    /// </summary>
    /// <param name="afterMark">The body that follows the byte order mark.</param>
    [TestMethod]
    [DataRow("<html><body><h1>502 Bad Gateway</h1></body></html>")]
    [DataRow(" \r\n<html><body><h1>502 Bad Gateway</h1></body></html>")]
    public void ParseTokenResponseRefusalOfAByteOrderMarkedHtmlBodyKeepsItsBody(string afterMark)
    {
        string body = (char)0xFEFF + afterMark;
        HttpResponseData response = Respond(body, statusCode: 502);

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        OAuthMalformedResponse malformed = Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
        Assert.AreEqual(body, malformed.Body, "An HTML document behind a byte order mark must be kept for diagnostics.");
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



    /// <summary>
    /// Parses a successful Token Response carrying <paramref name="authorizationDetails"/> as its
    /// <c>authorization_details</c> member and asserts the parse fails as an invalid value of that
    /// member.
    /// </summary>
    /// <param name="authorizationDetails">The literal member value the Token Response carries.</param>
    private static void AssertAuthorizationDetailsAreRefused(string authorizationDetails)
    {
        HttpResponseData response = Respond(
            $$"""{"access_token":"at","token_type":"Bearer","authorization_details":{{authorizationDetails}}}""");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess, "A malformed authorization_details member must fail the whole parse.");
        OAuthInvalidFieldValue invalid = Assert.IsInstanceOfType<OAuthInvalidFieldValue>(result.Error);
        Assert.AreEqual("authorization_details", invalid.FieldName);
    }


    /// <summary>
    /// Asserts a parse failed as an invalid value of <paramref name="fieldName"/> that echoes none of the
    /// value: the error's received value is empty and its string form does not hold
    /// <paramref name="refusedValue"/>.
    /// </summary>
    /// <param name="result">The parse result.</param>
    /// <param name="fieldName">The member the refusal must name.</param>
    /// <param name="refusedValue">A part of the refused value the error must not hold.</param>
    /// <returns>The refusal, for further assertions on its string form.</returns>
    private static OAuthInvalidFieldValue AssertRefusedWithoutItsValue(
        Result<TokenResponse, OAuthParseError> result, string fieldName, string refusedValue)
    {
        Assert.IsFalse(result.IsSuccess, $"The {fieldName} outside its grammar must fail the parse.");
        OAuthInvalidFieldValue invalid = Assert.IsInstanceOfType<OAuthInvalidFieldValue>(result.Error);
        Assert.AreEqual(fieldName, invalid.FieldName);
        Assert.IsEmpty(invalid.ReceivedValue, $"The refused {fieldName} must not be echoed in the error.");
        Assert.DoesNotContain(refusedValue, invalid.ToString(), StringComparison.Ordinal);

        return invalid;
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
