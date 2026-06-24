using System.Buffers;
using System.Collections.Generic;
using Verifiable.DidComm;
using Verifiable.DidComm.OutOfBand;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Decode-the-vector, round-trip, fail-closed-negative, shortened-URL, correlation, and QR-bound tests
/// for the DIDComm v2.1 Out-of-Band invitation surface —
/// <see cref="OutOfBandInvitationExtensions"/> over <see cref="DidCommMessageJson.Serializer"/> /
/// <see cref="DidCommMessageJson.Parser"/>, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#out-of-band-messages">DIDComm Messaging v2.1 §Out Of Band Messages</see>.
/// </summary>
[TestClass]
internal sealed class DidCommOutOfBandInvitationTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    //The DIDComm v2.1 §Example Out-of-Band Message Encoding base64url value (didcomm-v2.1.txt L1548).
    private const string SpecGoldenVectorOob =
        "eyJ0eXBlIjoiaHR0cHM6Ly9kaWRjb21tLm9yZy9vdXQtb2YtYmFuZC8yLjAvaW52aXRhdGlvbiIsImlkIjoiNjkyMTJhM2EtZDA2OC00ZjlkLWEyZGQtNDc0MWJjYTg5YWYzIiwiZnJvbSI6ImRpZDpleGFtcGxlOmFsaWNlIiwiYm9keSI6eyJnb2FsX2NvZGUiOiIiLCJnb2FsIjoiIn0sImF0dGFjaG1lbnRzIjpbeyJpZCI6InJlcXVlc3QtMCIsIm1lZGlhX3R5cGUiOiJhcHBsaWNhdGlvbi9qc29uIiwiZGF0YSI6eyJqc29uIjoiPGpzb24gb2YgcHJvdG9jb2wgbWVzc2FnZT4ifX1dfQ";

    //The §Example URL (didcomm-v2.1.txt L1552) the golden vector lands in.
    private const string SpecGoldenVectorBaseUrl = "https://example.com/path";


    /// <summary>
    /// The DIDComm v2.1 §Example Out-of-Band Message Encoding base64url vector decodes — through the
    /// test base64url decoder and <see cref="DidCommPlaintextExtensions.UnpackPlaintext"/> — into an
    /// invitation whose type / id / from / body / attachments match the spec example by property
    /// (order-independent — the JSON key order is non-normative).
    /// </summary>
    [TestMethod]
    public void SpecGoldenVectorDecodes()
    {
        using IMemoryOwner<byte> decoded = TestSetup.Base64UrlDecoder(SpecGoldenVectorOob, Pool);
        DidCommMessage invitation = DidCommPlaintextExtensions.UnpackPlaintext(decoded.Memory.Span, DidCommMessageJson.Parser);

        Assert.AreEqual("https://didcomm.org/out-of-band/2.0/invitation", invitation.Type);
        Assert.AreEqual("69212a3a-d068-4f9d-a2dd-4741bca89af3", invitation.Id);
        Assert.AreEqual("did:example:alice", invitation.From);
        Assert.IsTrue(invitation.IsOutOfBandInvitation());

        //body: {"goal_code":"","goal":""} — both empty strings in the spec example.
        Assert.IsNotNull(invitation.Body);
        Assert.AreEqual("", invitation.GetOutOfBandGoalCode());
        Assert.AreEqual("", invitation.GetOutOfBandGoal());
        Assert.HasCount(0, invitation.GetOutOfBandAccept());

        //attachments: a single request-0 attachment of application/json with data.json the placeholder.
        Assert.IsNotNull(invitation.Attachments);
        Assert.HasCount(1, invitation.Attachments);
        Attachment attachment = invitation.Attachments[0];
        Assert.AreEqual("request-0", attachment.Id);
        Assert.AreEqual("application/json", attachment.MediaType);
        Assert.IsNotNull(attachment.Data);
        Assert.AreEqual("<json of protocol message>", attachment.Data.Json);
    }


    /// <summary>
    /// A built invitation encodes to a <c>?_oob=</c> URL and parses back, field-equal — the
    /// build → encode → parse round-trip. The encoded URL carries the reserved <c>_oob</c> parameter
    /// on the base URL (DIDComm v2.1 §Standard Message Encoding).
    /// </summary>
    [TestMethod]
    public void BuildEncodeParseRoundTrips()
    {
        DidCommMessage invitation = OutOfBandInvitationExtensions.CreateOutOfBandInvitation(
            from: "did:example:alice",
            id: "69212a3a-d068-4f9d-a2dd-4741bca89af3",
            goalCode: "issue-vc",
            goal: "To issue a Faber College Graduate credential",
            accept: ["didcomm/v2", "didcomm/aip2;env=rfc587"]);

        string url = invitation.ToOutOfBandUrl(
            SpecGoldenVectorBaseUrl, DidCommMessageJson.Serializer, TestSetup.Base64UrlEncoder, Pool);

        //§Standard Message Encoding URL shape: <baseUrl>?_oob=<encodedplaintextjwm>.
        Assert.StartsWith(SpecGoldenVectorBaseUrl + "?_oob=", url, StringComparison.Ordinal);

        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            url, DidCommMessageJson.Parser, TestSetup.Base64UrlDecoder, Pool, out OutOfBandInvitationParseResult result);

        Assert.IsTrue(isParsed);
        Assert.AreEqual(OutOfBandUrlParseError.None, result.Error);
        Assert.IsNotNull(result.Invitation);
        Assert.AreEqual(invitation.Type, result.Invitation.Type);
        Assert.AreEqual(invitation.Id, result.Invitation.Id);
        Assert.AreEqual(invitation.From, result.Invitation.From);
        Assert.AreEqual("issue-vc", result.Invitation.GetOutOfBandGoalCode());
        Assert.AreEqual("To issue a Faber College Graduate credential", result.Invitation.GetOutOfBandGoal());
        CollectionAssert.AreEqual(
            new List<string> { "didcomm/v2", "didcomm/aip2;env=rfc587" },
            new List<string>(result.Invitation.GetOutOfBandAccept()));
    }


    /// <summary>
    /// The registry-resolving encode / parse overloads round-trip — they resolve the base64url codec
    /// from the <see cref="Verifiable.Cryptography.DefaultCoderSelector"/> the test wiring initialized.
    /// </summary>
    [TestMethod]
    public void RegistryResolvingOverloadsRoundTrip()
    {
        DidCommMessage invitation = OutOfBandInvitationExtensions.CreateOutOfBandInvitation(
            from: "did:example:alice",
            id: "69212a3a-d068-4f9d-a2dd-4741bca89af3");

        string url = invitation.ToOutOfBandUrl(SpecGoldenVectorBaseUrl, DidCommMessageJson.Serializer, Pool);

        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            url, DidCommMessageJson.Parser, Pool, out OutOfBandInvitationParseResult result);

        Assert.IsTrue(isParsed);
        Assert.IsNotNull(result.Invitation);
        Assert.AreEqual(invitation.Id, result.Invitation.Id);
        Assert.AreEqual(invitation.From, result.Invitation.From);
    }


    /// <summary>
    /// Encoding a base URL that already carries a query string joins the <c>_oob</c> parameter with
    /// <c>&amp;</c> (DIDComm v2.1 §Standard Message Encoding: additional query parameters are allowed).
    /// </summary>
    [TestMethod]
    public void EncodeAppendsWithAmpersandWhenBaseUrlHasQuery()
    {
        DidCommMessage invitation = OutOfBandInvitationExtensions.CreateOutOfBandInvitation(
            from: "did:example:alice", id: "1");

        string url = invitation.ToOutOfBandUrl(
            "https://example.com/path?ref=coupon", DidCommMessageJson.Serializer, TestSetup.Base64UrlEncoder, Pool);

        Assert.Contains("?ref=coupon&_oob=", url, StringComparison.Ordinal);

        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            url, DidCommMessageJson.Parser, TestSetup.Base64UrlDecoder, Pool, out OutOfBandInvitationParseResult result);

        Assert.IsTrue(isParsed);
        Assert.AreEqual("1", result.Invitation!.Id);
    }


    /// <summary>Encoding a non-invitation message throws on the producer side — a producer-side OOB MUST guard.</summary>
    [TestMethod]
    public void EncodingNonInvitationThrows()
    {
        var notAnInvitation = new DidCommMessage
        {
            Id = "1",
            Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
            From = "did:example:alice"
        };

        Assert.ThrowsExactly<ArgumentException>(() => notAnInvitation.ToOutOfBandUrl(
            SpecGoldenVectorBaseUrl, DidCommMessageJson.Serializer, TestSetup.Base64UrlEncoder, Pool));
    }


    /// <summary>A URL with no <c>_oob</c> parameter fails closed with <see cref="OutOfBandUrlParseError.OobUrlMissingParameter"/>.</summary>
    [TestMethod]
    public void ParseMissingOobParameterFailsClosed()
    {
        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            "https://example.com/path?other=1", DidCommMessageJson.Parser, TestSetup.Base64UrlDecoder, Pool,
            out OutOfBandInvitationParseResult result);

        Assert.IsFalse(isParsed);
        Assert.AreEqual(OutOfBandUrlParseError.OobUrlMissingParameter, result.Error);
        Assert.IsNull(result.Invitation);
    }


    /// <summary>A URL whose <c>_oob</c> value is not decodable base64url fails closed with <see cref="OutOfBandUrlParseError.OobValueMalformed"/>.</summary>
    [TestMethod]
    public void ParseMalformedBase64FailsClosed()
    {
        //'*' is not a base64url alphabet character, so the decoder rejects the value.
        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            "https://example.com/path?_oob=****", DidCommMessageJson.Parser, TestSetup.Base64UrlDecoder, Pool,
            out OutOfBandInvitationParseResult result);

        Assert.IsFalse(isParsed);
        Assert.AreEqual(OutOfBandUrlParseError.OobValueMalformed, result.Error);
        Assert.IsNull(result.Invitation);
    }


    /// <summary>A URL whose <c>_oob</c> value decodes to JSON that is not a structurally valid JWM fails closed with <see cref="OutOfBandUrlParseError.OobValueMalformed"/>.</summary>
    [TestMethod]
    public void ParseMalformedJsonFailsClosed()
    {
        //base64url of the bytes "{not json" — decodes, but is not parseable JSON.
        string oob = TestSetup.Base64UrlEncoder("{not json"u8);

        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            "https://example.com/path?_oob=" + oob, DidCommMessageJson.Parser, TestSetup.Base64UrlDecoder, Pool,
            out OutOfBandInvitationParseResult result);

        Assert.IsFalse(isParsed);
        Assert.AreEqual(OutOfBandUrlParseError.OobValueMalformed, result.Error);
        Assert.IsNull(result.Invitation);
    }


    /// <summary>A URL whose decoded message has a non-invitation <c>type</c> fails closed with <see cref="OutOfBandUrlParseError.OobNotAnInvitation"/>.</summary>
    [TestMethod]
    public void ParseWrongTypeFailsClosed()
    {
        string oob = TestSetup.Base64UrlEncoder(
            """{"id":"1","type":"https://example.com/protocols/lets_do_lunch/1.0/proposal","from":"did:example:alice"}"""u8);

        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            "https://example.com/path?_oob=" + oob, DidCommMessageJson.Parser, TestSetup.Base64UrlDecoder, Pool,
            out OutOfBandInvitationParseResult result);

        Assert.IsFalse(isParsed);
        Assert.AreEqual(OutOfBandUrlParseError.OobNotAnInvitation, result.Error);
        Assert.IsNull(result.Invitation);
    }


    /// <summary>
    /// A URL whose decoded invitation has no <c>from</c> fails closed with
    /// <see cref="OutOfBandUrlParseError.OobMissingFrom"/> — the invitation-type and id pass the
    /// structural validation, leaving the OOB-required from as the violated MUST.
    /// </summary>
    [TestMethod]
    public void ParseMissingFromFailsClosed()
    {
        string oob = TestSetup.Base64UrlEncoder(
            """{"id":"1","type":"https://didcomm.org/out-of-band/2.0/invitation"}"""u8);

        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            "https://example.com/path?_oob=" + oob, DidCommMessageJson.Parser, TestSetup.Base64UrlDecoder, Pool,
            out OutOfBandInvitationParseResult result);

        Assert.IsFalse(isParsed);
        Assert.AreEqual(OutOfBandUrlParseError.OobMissingFrom, result.Error);
        Assert.IsNull(result.Invitation);
    }


    /// <summary>
    /// A URL whose decoded message has no <c>id</c> fails closed with
    /// <see cref="OutOfBandUrlParseError.OobValueMalformed"/> — the missing id is caught by the
    /// §Message Headers structural validation before the OOB-specific id check is reached.
    /// </summary>
    [TestMethod]
    public void ParseMissingIdFailsClosed()
    {
        string oob = TestSetup.Base64UrlEncoder(
            """{"type":"https://didcomm.org/out-of-band/2.0/invitation","from":"did:example:alice"}"""u8);

        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            "https://example.com/path?_oob=" + oob, DidCommMessageJson.Parser, TestSetup.Base64UrlDecoder, Pool,
            out OutOfBandInvitationParseResult result);

        Assert.IsFalse(isParsed);
        Assert.AreEqual(OutOfBandUrlParseError.OobValueMalformed, result.Error);
        Assert.IsNull(result.Invitation);
    }


    /// <summary>
    /// The §Short URL Message Retrieval form round-trips: encode <c>?_oobid=&lt;id&gt;</c> and extract
    /// the id back (DIDComm v2.1 §Short URL Message Retrieval).
    /// </summary>
    [TestMethod]
    public void ShortenedUrlRoundTrips()
    {
        const string OobId = "5f0e3ffb-3f92-4648-9868-0d6f8889e6f3";

        string url = OutOfBandInvitationExtensions.ToShortenedOutOfBandUrl(SpecGoldenVectorBaseUrl, OobId);

        Assert.AreEqual("https://example.com/path?_oobid=5f0e3ffb-3f92-4648-9868-0d6f8889e6f3", url);

        bool isExtracted = OutOfBandInvitationExtensions.TryGetShortenedOutOfBandId(url, out string? extracted);

        Assert.IsTrue(isExtracted);
        Assert.AreEqual(OobId, extracted);
    }


    /// <summary>A URL with no <c>_oobid</c> parameter yields false with a null id and never throws.</summary>
    [TestMethod]
    public void ShortenedUrlExtractMissingIdFailsClosed()
    {
        bool isExtracted = OutOfBandInvitationExtensions.TryGetShortenedOutOfBandId(
            "https://example.com/path?other=1", out string? extracted);

        Assert.IsFalse(isExtracted);
        Assert.IsNull(extracted);
    }


    /// <summary>
    /// Correlating a response sets the response <c>pthid</c> to the invitation <c>id</c> (DIDComm v2.1
    /// §Message Correlation: the URL/QR message id becomes the response's parent thread id).
    /// </summary>
    [TestMethod]
    public void CorrelationSetsResponsePthidToInvitationId()
    {
        DidCommMessage invitation = OutOfBandInvitationExtensions.CreateOutOfBandInvitation(
            from: "did:example:alice", id: "69212a3a-d068-4f9d-a2dd-4741bca89af3");

        var response = new DidCommMessage
        {
            Id = "response-1",
            Type = "https://didcomm.org/connections/1.0/response",
            From = "did:example:bob"
        };

        response.CorrelateToOutOfBandInvitation(invitation);

        Assert.AreEqual("69212a3a-d068-4f9d-a2dd-4741bca89af3", response.ParentThreadId);
    }


    /// <summary>A short URL validates as a QR-encodable URL with no advisory and within the hard bound.</summary>
    [TestMethod]
    public void QrBoundsShortUrlIsValidNoAdvisory()
    {
        OutOfBandUrlValidation validation = OutOfBandInvitationExtensions.ValidateOutOfBandQrBounds(
            "https://example.com/path?_oob=eyJ0eXBlIjoi");

        Assert.IsTrue(validation.IsValid);
        Assert.IsFalse(validation.HasAdvisory);
    }


    /// <summary>
    /// A URL between the advisory and hard bounds validates with the advisory flag set; a URL past the
    /// hard bound is not valid (DIDComm v2.1 §Short URL Message Retrieval: the sender then uses the
    /// shortened form).
    /// </summary>
    [TestMethod]
    public void QrBoundsAdvisoryAndHardLimits()
    {
        string advisoryUrl = "https://example.com/path?_oob=" + new string('a', OutOfBandInvitationExtensions.QrAdvisoryLength);
        OutOfBandUrlValidation advisory = OutOfBandInvitationExtensions.ValidateOutOfBandQrBounds(advisoryUrl);

        Assert.IsTrue(advisory.IsValid);
        Assert.IsTrue(advisory.HasAdvisory);

        string oversizeUrl = "https://example.com/path?_oob=" + new string('a', OutOfBandInvitationExtensions.QrMaximumLength);
        OutOfBandUrlValidation oversize = OutOfBandInvitationExtensions.ValidateOutOfBandQrBounds(oversizeUrl);

        Assert.IsFalse(oversize.IsValid);
    }


    /// <summary>
    /// The QR bounds are inclusive: a URL whose total length equals exactly <see cref="OutOfBandInvitationExtensions.QrAdvisoryLength"/>
    /// is valid with NO advisory, and one equal to exactly <see cref="OutOfBandInvitationExtensions.QrMaximumLength"/>
    /// is valid WITH the advisory — pinning the off-by-one boundaries.
    /// </summary>
    [TestMethod]
    public void QrBoundsInclusiveLimitsArePinned()
    {
        const string prefix = "https://example.com/path?_oob=";

        string atAdvisory = prefix + new string('a', OutOfBandInvitationExtensions.QrAdvisoryLength - prefix.Length);
        OutOfBandUrlValidation advisory = OutOfBandInvitationExtensions.ValidateOutOfBandQrBounds(atAdvisory);

        Assert.AreEqual(OutOfBandInvitationExtensions.QrAdvisoryLength, advisory.UrlLength);
        Assert.IsTrue(advisory.IsValid);
        Assert.IsFalse(advisory.HasAdvisory, "A URL exactly at the advisory bound MUST NOT set the advisory flag (inclusive bound).");

        string atHard = prefix + new string('a', OutOfBandInvitationExtensions.QrMaximumLength - prefix.Length);
        OutOfBandUrlValidation hard = OutOfBandInvitationExtensions.ValidateOutOfBandQrBounds(atHard);

        Assert.AreEqual(OutOfBandInvitationExtensions.QrMaximumLength, hard.UrlLength);
        Assert.IsTrue(hard.IsValid, "A URL exactly at the hard bound MUST still be valid (inclusive bound).");
        Assert.IsTrue(hard.HasAdvisory);
    }


    /// <summary>
    /// An <c>_oob</c> value past the hard length bound is rejected BEFORE decoding with
    /// <see cref="OutOfBandUrlParseError.OobValueTooLong"/>, so a hostile value cannot drive an unbounded
    /// pool allocation; it fails closed and never throws (DIDComm v2.1 §Privacy Considerations).
    /// </summary>
    [TestMethod]
    public void ParseOversizedOobValueFailsClosed()
    {
        string url = "https://example.com/path?_oob=" + new string('A', OutOfBandInvitationExtensions.MaximumOobValueLength + 1);

        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            url, DidCommMessageJson.Parser, TestSetup.Base64UrlDecoder, Pool, out OutOfBandInvitationParseResult result);

        Assert.IsFalse(isParsed);
        Assert.AreEqual(OutOfBandUrlParseError.OobValueTooLong, result.Error);
        Assert.IsNull(result.Invitation);
    }


    /// <summary>
    /// A URL carrying the reserved <c>_oob</c> parameter more than once is ambiguous and rejected with
    /// <see cref="OutOfBandUrlParseError.OobUrlAmbiguousParameter"/> rather than silently taking the first.
    /// </summary>
    [TestMethod]
    public void ParseDuplicateOobParameterFailsClosed()
    {
        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            "https://example.com/path?_oob=AAAA&_oob=BBBB", DidCommMessageJson.Parser, TestSetup.Base64UrlDecoder, Pool,
            out OutOfBandInvitationParseResult result);

        Assert.IsFalse(isParsed);
        Assert.AreEqual(OutOfBandUrlParseError.OobUrlAmbiguousParameter, result.Error);
        Assert.IsNull(result.Invitation);
    }


    /// <summary>
    /// A URL carrying both the by-value <c>_oob</c> and the shortened-form <c>_oobid</c> is ambiguous and
    /// rejected with <see cref="OutOfBandUrlParseError.OobUrlAmbiguousParameter"/>.
    /// </summary>
    [TestMethod]
    public void ParseOobAlongsideOobIdFailsClosed()
    {
        bool isParsed = OutOfBandInvitationExtensions.TryParseOutOfBandUrl(
            "https://example.com/path?_oob=AAAA&_oobid=5f0e3ffb-3f92-4648-9868-0d6f8889e6f3", DidCommMessageJson.Parser, TestSetup.Base64UrlDecoder, Pool,
            out OutOfBandInvitationParseResult result);

        Assert.IsFalse(isParsed);
        Assert.AreEqual(OutOfBandUrlParseError.OobUrlAmbiguousParameter, result.Error);
        Assert.IsNull(result.Invitation);
    }
}
