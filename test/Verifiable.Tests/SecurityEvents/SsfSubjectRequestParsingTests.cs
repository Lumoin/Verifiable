using Verifiable.Core.SecurityEvents;
using Verifiable.Json;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Tests for the Stream Management Subject (§8.1.3) and Verification (§8.1.4)
/// request parsers in <see cref="SsfStreamJsonParsing"/>.
/// </summary>
[TestClass]
internal sealed class SsfSubjectRequestParsingTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void AddSubjectRequestParses()
    {
        SsfAddSubjectRequest? request = SsfStreamJsonParsing.ParseAddSubjectRequest("""
        {
            "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
            "subject": { "format": "email", "email": "example.user@example.com" },
            "verified": true
        }
        """);

        Assert.IsNotNull(request);
        Assert.AreEqual("f67e39a0a4d34d56b3aa1bc4cff0069f", request.StreamId);
        Assert.AreEqual(SubjectIdentifierFormats.Email, request.Subject.Format);
        Assert.IsTrue(request.Subject.IsValidForKnownFormat());
        Assert.IsNotNull(request.Verified);
        Assert.IsTrue(request.Verified.Value);
    }


    [TestMethod]
    public void AddSubjectWithoutVerifiedLeavesItNull()
    {
        SsfAddSubjectRequest? request = SsfStreamJsonParsing.ParseAddSubjectRequest("""
        { "stream_id": "s1", "subject": { "format": "opaque", "id": "abc" } }
        """);

        Assert.IsNotNull(request);
        Assert.IsNull(request.Verified);
        Assert.AreEqual(SubjectIdentifierFormats.Opaque, request.Subject.Format);
    }


    [TestMethod]
    public void AddSubjectWithComplexSubjectParses()
    {
        SsfAddSubjectRequest? request = SsfStreamJsonParsing.ParseAddSubjectRequest("""
        {
            "stream_id": "s1",
            "subject": {
                "format": "complex",
                "user": { "format": "iss_sub", "iss": "https://idp.example/", "sub": "u1" }
            }
        }
        """);

        Assert.IsNotNull(request);
        Assert.AreEqual(SubjectIdentifierFormats.Complex, request.Subject.Format);
        Assert.IsTrue(request.Subject.IsValidForKnownFormat());
    }


    [TestMethod]
    public void RemoveSubjectRequestParses()
    {
        SsfRemoveSubjectRequest? request = SsfStreamJsonParsing.ParseRemoveSubjectRequest("""
        { "stream_id": "s1", "subject": { "format": "phone_number", "phone_number": "+12065550123" } }
        """);

        Assert.IsNotNull(request);
        Assert.AreEqual("s1", request.StreamId);
        Assert.AreEqual(SubjectIdentifierFormats.PhoneNumber, request.Subject.Format);
    }


    [TestMethod]
    public void SubjectMissingOrMalformedIsRejected()
    {
        //Missing subject.
        Assert.IsNull(SsfStreamJsonParsing.ParseAddSubjectRequest("""{ "stream_id": "s1" }"""));
        //Subject object without a format member is not a Subject Identifier.
        Assert.IsNull(SsfStreamJsonParsing.ParseAddSubjectRequest(
            """{ "stream_id": "s1", "subject": { "email": "x@example.com" } }"""));
        //Missing stream_id.
        Assert.IsNull(SsfStreamJsonParsing.ParseRemoveSubjectRequest(
            """{ "subject": { "format": "opaque", "id": "abc" } }"""));
    }


    [TestMethod]
    public void VerificationRequestParses()
    {
        SsfVerificationRequest? request = SsfStreamJsonParsing.ParseVerificationRequest("""
        { "stream_id": "s1", "state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRl" }
        """);

        Assert.IsNotNull(request);
        Assert.AreEqual("s1", request.StreamId);
        Assert.AreEqual("VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRl", request.State);
    }


    [TestMethod]
    public void VerificationRequestWithoutStateParses()
    {
        SsfVerificationRequest? request = SsfStreamJsonParsing.ParseVerificationRequest("""{ "stream_id": "s1" }""");

        Assert.IsNotNull(request);
        Assert.IsNull(request.State);
    }


    [TestMethod]
    public void VerificationRequestMissingStreamIdIsRejected() =>
        Assert.IsNull(SsfStreamJsonParsing.ParseVerificationRequest("""{ "state": "abc" }"""));
}
