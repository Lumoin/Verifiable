using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Round-trip, test-vector, validation, and arbitrary-content tests for the DIDComm plaintext
/// message JSON pipeline — <see cref="DidCommMessageJson.Serializer"/> /
/// <see cref="DidCommMessageJson.Parser"/> driving
/// <see cref="DidCommPlaintextExtensions.PackPlaintext"/> /
/// <see cref="DidCommPlaintextExtensions.UnpackPlaintext"/>.
/// </summary>
[TestClass]
internal sealed class DidCommPlaintextMessageTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// A message carrying a body, an attachment, and a non-standard extension header round-trips
    /// through pack/unpack with every known field and the extension header preserved, and the
    /// serialized form is an <c>application/didcomm-plain+json</c>-compatible JSON object with the
    /// wire member names.
    /// </summary>
    [TestMethod]
    public void RoundTripPreservesKnownFieldsAndExtensionHeader()
    {
        var message = new DidCommMessage
        {
            Id = "1234567890",
            Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
            From = "did:example:alice",
            To = ["did:example:bob"],
            ThreadId = "thread-1",
            ParentThreadId = "parent-1",
            CreatedTime = 1516269022,
            ExpiresTime = 1516385931,
            FromPrior = "<from-prior-jwt>",
            Body = new Dictionary<string, object>
            {
                ["messagespecificattribute"] = "and its value",
                ["count"] = 42
            },
            Attachments =
            [
                new Attachment
                {
                    Id = "1",
                    Description = "example b64 encoded attachment",
                    MediaType = "application/json",
                    Data = new AttachmentData
                    {
                        Base64 = "WW91ciBob3ZlcmNyYWZ0IGlzIGZ1bGwgb2YgZWVscw=="
                    }
                }
            ],
            AdditionalHeaders = new Dictionary<string, object>
            {
                ["custom_header"] = "extension value"
            }
        };

        using DidCommPlaintextMessage packed = message.PackPlaintext(DidCommMessageJson.Serializer, Pool);

        //The serialized form MUST be a JSON object carrying the wire member names.
        using(var document = JsonDocument.Parse(packed.AsReadOnlyMemory()))
        {
            Assert.AreEqual(JsonValueKind.Object, document.RootElement.ValueKind);
            Assert.IsTrue(document.RootElement.TryGetProperty("id", out _));
            Assert.IsTrue(document.RootElement.TryGetProperty("created_time", out _));
            Assert.IsTrue(document.RootElement.TryGetProperty("from_prior", out _));
            Assert.IsTrue(document.RootElement.TryGetProperty("custom_header", out _));
            Assert.IsTrue(document.RootElement.TryGetProperty("attachments", out _));
        }

        DidCommMessage roundTripped = packed.UnpackPlaintext(DidCommMessageJson.Parser);

        Assert.AreEqual(message.Id, roundTripped.Id);
        Assert.AreEqual(message.Type, roundTripped.Type);
        Assert.AreEqual(message.From, roundTripped.From);
        Assert.AreSequenceEqual((List<string>)message.To!, (List<string>)roundTripped.To!);
        Assert.AreEqual(message.ThreadId, roundTripped.ThreadId);
        Assert.AreEqual(message.ParentThreadId, roundTripped.ParentThreadId);
        Assert.AreEqual(message.CreatedTime, roundTripped.CreatedTime);
        Assert.AreEqual(message.ExpiresTime, roundTripped.ExpiresTime);
        Assert.AreEqual(message.FromPrior, roundTripped.FromPrior);

        Assert.IsNotNull(roundTripped.Body);
        Assert.AreEqual("and its value", roundTripped.Body["messagespecificattribute"]);
        Assert.AreEqual(42, roundTripped.Body["count"]);

        Assert.IsNotNull(roundTripped.Attachments);
        Assert.HasCount(1, roundTripped.Attachments);
        Attachment attachment = roundTripped.Attachments[0];
        Assert.AreEqual("1", attachment.Id);
        Assert.AreEqual("example b64 encoded attachment", attachment.Description);
        Assert.AreEqual("application/json", attachment.MediaType);
        Assert.IsNotNull(attachment.Data);
        Assert.AreEqual("WW91ciBob3ZlcmNyYWZ0IGlzIGZ1bGwgb2YgZWVscw==", attachment.Data.Base64);

        //The extension header survives the round trip.
        Assert.IsNotNull(roundTripped.AdditionalHeaders);
        Assert.AreEqual("extension value", roundTripped.AdditionalHeaders["custom_header"]);
    }


    /// <summary>
    /// The DIDComm v2.1 Appendix C.1 Plaintext Message test vector parses into the expected
    /// header values through unpack.
    /// </summary>
    /// <remarks>
    /// The vector (DIDComm Messaging v2.1 §Appendix C.1) is:
    /// <code>
    /// {
    ///    "id":"1234567890",
    ///    "type":"https://example.com/protocols/lets_do_lunch/1.0/proposal",
    ///    "from":"did:example:alice",
    ///    "to":["did:example:bob"],
    ///    "created_time":1516269022,
    ///    "expires_time":1516385931,
    ///    "body":{"messagespecificattribute":"and its value"}
    /// }
    /// </code>
    /// </remarks>
    [TestMethod]
    public void AppendixC1VectorParses()
    {
        const string AppendixC1 = """
            {
               "id":"1234567890",
               "type":"https://example.com/protocols/lets_do_lunch/1.0/proposal",
               "from":"did:example:alice",
               "to":[
                  "did:example:bob"
               ],
               "created_time":1516269022,
               "expires_time":1516385931,
               "body":{
                  "messagespecificattribute":"and its value"
               }
            }
            """;

        byte[] plaintextJson = Encoding.UTF8.GetBytes(AppendixC1);

        DidCommMessage message = DidCommPlaintextExtensions.UnpackPlaintext(plaintextJson, DidCommMessageJson.Parser);

        Assert.AreEqual("1234567890", message.Id);
        Assert.AreEqual("https://example.com/protocols/lets_do_lunch/1.0/proposal", message.Type);
        Assert.AreEqual("did:example:alice", message.From);
        Assert.IsNotNull(message.To);
        Assert.HasCount(1, message.To);
        Assert.AreEqual("did:example:bob", message.To[0]);
        Assert.AreEqual(1516269022L, message.CreatedTime);
        Assert.AreEqual(1516385931L, message.ExpiresTime);
        Assert.IsNotNull(message.Body);
        Assert.AreEqual("and its value", message.Body["messagespecificattribute"]);
    }


    /// <summary>A message missing the required <c>id</c> header is rejected by unpack.</summary>
    [TestMethod]
    public void MissingIdIsRejected()
    {
        const string Json = """
            {"type":"https://example.com/protocols/lets_do_lunch/1.0/proposal"}
            """;

        Assert.ThrowsExactly<FormatException>(() =>
            DidCommPlaintextExtensions.UnpackPlaintext(Encoding.UTF8.GetBytes(Json), DidCommMessageJson.Parser));
    }


    /// <summary>A message missing the required <c>type</c> header is rejected by unpack.</summary>
    [TestMethod]
    public void MissingTypeIsRejected()
    {
        const string Json = """
            {"id":"1234567890"}
            """;

        Assert.ThrowsExactly<FormatException>(() =>
            DidCommPlaintextExtensions.UnpackPlaintext(Encoding.UTF8.GetBytes(Json), DidCommMessageJson.Parser));
    }


    /// <summary>A message whose <c>type</c> is not a valid Message Type URI is rejected by unpack.</summary>
    [TestMethod]
    public void NonMessageTypeUriTypeIsRejected()
    {
        const string Json = """
            {"id":"1234567890","type":"not a message type uri"}
            """;

        Assert.ThrowsExactly<FormatException>(() =>
            DidCommPlaintextExtensions.UnpackPlaintext(Encoding.UTF8.GetBytes(Json), DidCommMessageJson.Parser));
    }


    /// <summary>A <c>to</c> entry carrying a fragment is rejected — recipients are DIDs or DID URLs without a fragment.</summary>
    [TestMethod]
    public void RecipientWithFragmentIsRejected()
    {
        const string Json = """
            {
               "id":"1234567890",
               "type":"https://example.com/protocols/lets_do_lunch/1.0/proposal",
               "to":["did:example:bob#keys-1"]
            }
            """;

        Assert.ThrowsExactly<FormatException>(() =>
            DidCommPlaintextExtensions.UnpackPlaintext(Encoding.UTF8.GetBytes(Json), DidCommMessageJson.Parser));
    }


    /// <summary>
    /// A <c>created_time</c> that is a fractional (non-integer) JSON number is rejected at the wire
    /// level. The converter enforces the integer typing and surfaces the violation as a
    /// <see cref="JsonException"/>, which propagates out of the parser delegate.
    /// </summary>
    [TestMethod]
    public void FractionalCreatedTimeIsRejected()
    {
        //Built by hand: a fractional created_time is not a JSON integer.
        const string Json = """
            {
               "id":"1234567890",
               "type":"https://example.com/protocols/lets_do_lunch/1.0/proposal",
               "created_time":1516269022.5
            }
            """;

        byte[] plaintextJson = Encoding.UTF8.GetBytes(Json);

        Assert.ThrowsExactly<JsonException>(() =>
            DidCommPlaintextExtensions.UnpackPlaintext(plaintextJson, DidCommMessageJson.Parser));
    }


    /// <summary>
    /// A <c>created_time</c> that is a JSON string (a different <c>ValueKind</c> than the fractional
    /// case) is also rejected — the wire-level guard requires a JSON integer, not merely a parseable
    /// numeric string.
    /// </summary>
    [TestMethod]
    public void StringCreatedTimeIsRejected()
    {
        const string Json = """
            {
               "id":"1234567890",
               "type":"https://example.com/protocols/lets_do_lunch/1.0/proposal",
               "created_time":"1516269022"
            }
            """;

        byte[] plaintextJson = Encoding.UTF8.GetBytes(Json);

        Assert.ThrowsExactly<JsonException>(() =>
            DidCommPlaintextExtensions.UnpackPlaintext(plaintextJson, DidCommMessageJson.Parser));
    }


    /// <summary>An unrecognized top-level header is carried verbatim into AdditionalHeaders and never causes failure.</summary>
    [TestMethod]
    public void UnknownHeaderIsPreservedThroughUnpack()
    {
        const string Json = """
            {
               "id":"1234567890",
               "type":"https://example.com/protocols/lets_do_lunch/1.0/proposal",
               "custom_array":["receipt"],
               "custom_scalar":7
            }
            """;

        DidCommMessage message = DidCommPlaintextExtensions.UnpackPlaintext(
            Encoding.UTF8.GetBytes(Json), DidCommMessageJson.Parser);

        Assert.IsNotNull(message.AdditionalHeaders);
        Assert.IsTrue(message.AdditionalHeaders.ContainsKey("custom_array"));
        Assert.AreEqual(7, message.AdditionalHeaders["custom_scalar"]);

        List<object> custom = (List<object>)message.AdditionalHeaders["custom_array"];
        Assert.HasCount(1, custom);
        Assert.AreEqual("receipt", custom[0]);
    }


    /// <summary>
    /// The three attachment shapes from the spec's Attachment Example round-trip: base64 inline,
    /// links+hash by-reference, and an embedded json attachment.
    /// </summary>
    [TestMethod]
    public void AttachmentShapesRoundTrip()
    {
        var message = new DidCommMessage
        {
            Id = "1234567890",
            Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
            To = ["did:example:mediator"],
            Attachments =
            [
                new Attachment
                {
                    Id = "1",
                    Description = "example b64 encoded attachment",
                    Data = new AttachmentData
                    {
                        Base64 = "WW91ciBob3ZlcmNyYWZ0IGlzIGZ1bGwgb2YgZWVscw=="
                    }
                },
                new Attachment
                {
                    Id = "2",
                    Description = "example linked attachment",
                    ByteCount = 1024,
                    Data = new AttachmentData
                    {
                        Hash = "<multi-hash>",
                        Links = ["https://path/to/resource"]
                    }
                },
                new Attachment
                {
                    Id = "x",
                    Description = "example embedded json attachment",
                    MediaType = "application/json",
                    Data = new AttachmentData
                    {
                        Json = new Dictionary<string, object>
                        {
                            ["protocol"] = "https://didcomm.org/x/1.0",
                            ["nested"] = new Dictionary<string, object> { ["k"] = "v" }
                        }
                    }
                }
            ]
        };

        using DidCommPlaintextMessage packed = message.PackPlaintext(DidCommMessageJson.Serializer, Pool);
        DidCommMessage roundTripped = packed.UnpackPlaintext(DidCommMessageJson.Parser);

        Assert.IsNotNull(roundTripped.Attachments);
        Assert.HasCount(3, roundTripped.Attachments);

        //Base64 inline.
        AttachmentData base64Data = roundTripped.Attachments[0].Data!;
        Assert.AreEqual("WW91ciBob3ZlcmNyYWZ0IGlzIGZ1bGwgb2YgZWVscw==", base64Data.Base64);

        //Links + hash by-reference.
        Attachment linked = roundTripped.Attachments[1];
        Assert.AreEqual(1024L, linked.ByteCount);
        Assert.AreEqual("<multi-hash>", linked.Data!.Hash);
        Assert.IsNotNull(linked.Data.Links);
        Assert.AreEqual("https://path/to/resource", linked.Data.Links[0]);

        //Embedded json.
        AttachmentData jsonData = roundTripped.Attachments[2].Data!;
        Assert.IsNotNull(jsonData.Json);
        var embedded = (Dictionary<string, object>)jsonData.Json;
        Assert.AreEqual("https://didcomm.org/x/1.0", embedded["protocol"]);
        var nested = (Dictionary<string, object>)embedded["nested"];
        Assert.AreEqual("v", nested["k"]);
    }


    /// <summary>
    /// The effective thread id defaults to the message id when no <c>thid</c> is present (DIDComm v2.1
    /// §Threading: "if the thid header is not included, the id of the current message MUST be used"), and is
    /// the explicit <c>thid</c> otherwise.
    /// </summary>
    [TestMethod]
    public void EffectiveThreadIdDefaultsToMessageId()
    {
        var firstInThread = new DidCommMessage { Id = "msg-1" };
        Assert.AreEqual("msg-1", firstInThread.EffectiveThreadId, "With no thid, the message id MUST be the effective thread id.");

        var reply = new DidCommMessage { Id = "msg-2", ThreadId = "msg-1" };
        Assert.AreEqual("msg-1", reply.EffectiveThreadId, "With a thid present, it MUST be the effective thread id.");

        var empty = new DidCommMessage();
        Assert.IsNull(empty.EffectiveThreadId, "With neither id nor thid, the effective thread id is null.");

        //An empty thid is malformed, not a real thread: it MUST fall back to the id, not collapse
        //otherwise-unrelated messages onto one empty thread.
        var emptyThid = new DidCommMessage { Id = "msg-3", ThreadId = "" };
        Assert.AreEqual("msg-3", emptyThid.EffectiveThreadId, "An empty thid MUST be treated as absent and fall back to the id.");
    }
}
