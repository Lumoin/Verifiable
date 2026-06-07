using Verifiable.Core.SecurityEvents;
using Verifiable.Json;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Tests for <see cref="SsfPollJsonParsing"/> — the RFC 8936 poll request and
/// response parsers.
/// </summary>
[TestClass]
internal sealed class SsfPollParsingTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void CombinedPollRequestParses()
    {
        SsfPollRequest? request = SsfPollJsonParsing.ParsePollRequest("""
        {
            "maxEvents": 5,
            "returnImmediately": true,
            "ack": ["jti-1", "jti-2"],
            "setErrs": {
                "jti-3": { "err": "invalid_issuer", "description": "Not authorized for issuer" }
            }
        }
        """);

        Assert.IsNotNull(request);
        Assert.AreEqual(5, request.MaxEvents);
        Assert.IsNotNull(request.ReturnImmediately);
        Assert.IsTrue(request.ReturnImmediately.Value);
        Assert.HasCount(2, request.Acks);
        Assert.HasCount(1, request.SetErrors);
        Assert.IsTrue(SsfDeliveryErrorCodes.IsInvalidIssuer(request.SetErrors["jti-3"].Err));
        Assert.AreEqual("Not authorized for issuer", request.SetErrors["jti-3"].Description);
    }


    [TestMethod]
    public void EmptyPollRequestIsPollOnly()
    {
        SsfPollRequest? request = SsfPollJsonParsing.ParsePollRequest("{}");

        Assert.IsNotNull(request);
        Assert.IsNull(request.MaxEvents);
        Assert.IsNull(request.ReturnImmediately);
        Assert.IsEmpty(request.Acks);
        Assert.IsEmpty(request.SetErrors);
    }


    [TestMethod]
    public void AcknowledgeOnlyPollRequestParses()
    {
        SsfPollRequest? request = SsfPollJsonParsing.ParsePollRequest("""
        { "maxEvents": 0, "ack": ["jti-1"] }
        """);

        Assert.IsNotNull(request);
        Assert.AreEqual(0, request.MaxEvents);
        Assert.HasCount(1, request.Acks);
    }


    [TestMethod]
    public void PollRequestSetErrMissingErrIsRejected() =>
        Assert.IsNull(SsfPollJsonParsing.ParsePollRequest("""
        { "setErrs": { "jti-3": { "description": "no code" } } }
        """));


    [TestMethod]
    public void NonObjectPollRequestIsRejected() =>
        Assert.IsNull(SsfPollJsonParsing.ParsePollRequest("[]"));


    [TestMethod]
    public void PollResponseParses()
    {
        SsfPollResponse? response = SsfPollJsonParsing.ParsePollResponse("""
        {
            "sets": {
                "jti-1": "eyJhbGciOiJFUzI1NiJ9.payload.sig",
                "jti-2": "eyJhbGciOiJFUzI1NiJ9.payload2.sig2"
            },
            "moreAvailable": true
        }
        """);

        Assert.IsNotNull(response);
        Assert.HasCount(2, response.Sets);
        Assert.AreEqual("eyJhbGciOiJFUzI1NiJ9.payload.sig", response.Sets["jti-1"]);
        Assert.IsTrue(response.MoreAvailable);
    }


    [TestMethod]
    public void EmptyPollResponseHasNoSetsAndMoreAvailableFalse()
    {
        SsfPollResponse? response = SsfPollJsonParsing.ParsePollResponse("{}");

        Assert.IsNotNull(response);
        Assert.IsEmpty(response.Sets);
        Assert.IsFalse(response.MoreAvailable);
    }


    [TestMethod]
    public void PollResponseWithNonStringSetValueIsRejected() =>
        Assert.IsNull(SsfPollJsonParsing.ParsePollResponse("""{ "sets": { "jti-1": 42 } }"""));
}
