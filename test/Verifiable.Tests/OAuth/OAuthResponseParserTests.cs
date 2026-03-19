using System;
using System.Collections.Generic;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="OAuthResponseParsers"/> covering RFC 9126 §2.2,
/// RFC 6749 §5.1/5.2, and RFC 9457 response shapes.
/// </summary>
[TestClass]
internal sealed class OAuthResponseParsersTests
{

    [TestMethod]
    public void ParseParResponseSucceedsForMinimalValidResponse()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}""");

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("urn:ietf:params:oauth:request_uri:abc",
            result.Value!.RequestUri.ToString());
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
        Assert.AreEqual(90, result.Value!.ExpiresIn);
    }

    [TestMethod]
    public void ParseParResponseSucceedsWhenFieldsAreReversed()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"expires_in":45,"request_uri":"urn:ietf:params:oauth:request_uri:rev"}""");

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(45, result.Value!.ExpiresIn);
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
        string? statusCode = result.Error!.Support.Context?[HttpResponseDataKeys.StatusCode];
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
        Assert.AreEqual("00-abc123-def456-01", result.Error!.Support.CorrelationId,
            "traceparent must become the CorrelationId on the DecisionSupport.");
    }



    [TestMethod]
    public void ParseParResponseReturnsMalformedForEmptyBody()
    {
        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(Respond(string.Empty));

        Assert.IsFalse(result.IsSuccess);
        Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
    }

    [TestMethod]
    public void ParseParResponseReturnsMalformedWhenRequestUriMissing()
    {
        HttpResponseData response = Respond(
            /*lang=json,strict*/ """{"expires_in":60}""");

        Result<ParResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseParResponse(response);

        Assert.IsFalse(result.IsSuccess);
        Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
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
            contentType: "application/problem+json");

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
        Assert.AreEqual("tok123", result.Value!.AccessToken);
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
        Assert.AreEqual("rt", result.Value!.RefreshToken);
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
        Assert.IsNull(result.Value!.ExpiresIn,
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
        Assert.IsInstanceOfType<OAuthMalformedResponse>(result.Error);
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
            contentType: "application/problem+json");

        Result<TokenResponse, OAuthParseError> result =
            OAuthResponseParsers.ParseTokenResponse(response, DateTimeOffset.UnixEpoch);

        Assert.IsFalse(result.IsSuccess);
        OAuthProtocolError pe =
            Assert.IsInstanceOfType<OAuthProtocolError>(result.Error);
        Assert.AreEqual("invalid_grant", pe.ErrorCode);
        Assert.AreEqual("urn:uuid:xyz-789", pe.Support.CorrelationId);
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
            transport = new Dictionary<string, string>();
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