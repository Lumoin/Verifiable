using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Verifiable.DidComm;
using Verifiable.DidComm.BasicMessage;
using Verifiable.Foundation;
using Verifiable.Json;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Tests for the DIDComm Basic Message Protocol 2.0 (<see cref="BasicMessageExtensions"/>): the build +
/// interpret round trip, the <c>created_time</c> standard header, the <c>lang</c> header carried as a
/// top-level sibling of <c>body</c> (not inside it), the semver-aware discriminator, and the fail-closed
/// interpret battery.
/// </summary>
[TestClass]
internal sealed class DidCommBasicMessageTests
{
    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    private const string Alice = "did:example:alice";
    private const string Bob = "did:example:bob";


    [TestMethod]
    public void BasicMessageRoundTrips()
    {
        var basic = new BasicMessage { Content = "Your hovercraft is full of eels." };
        DidCommMessage message = basic.CreateBasicMessage("bm-1", from: Alice, createdTime: 1547577721, to: [Bob]);

        Assert.IsTrue(message.IsBasicMessage());
        Assert.AreEqual(WellKnownBasicMessageNames.MessageType, message.Type);

        string json = PackToJson(message);
        Assert.Contains("basicmessage/2.0/message", json, "The basic message type URI.");
        Assert.Contains("\"content\":\"Your hovercraft is full of eels.\"", json, "The content sits in the body verbatim.");

        DidCommMessage parsed = RoundTrip(message);
        Assert.AreEqual(1547577721, parsed.CreatedTime, "created_time round-trips as the standard header.");
        Assert.IsTrue(parsed.TryInterpretBasicMessage(out BasicMessage? recovered));
        Assert.AreEqual("Your hovercraft is full of eels.", recovered!.Content);
        Assert.IsNull(recovered.Lang, "No lang header was set.");
    }


    [TestMethod]
    public void LangHeaderRoundTripsAsTopLevelSibling()
    {
        var basic = new BasicMessage { Content = "Hei maailma", Lang = "fi" };
        DidCommMessage message = basic.CreateBasicMessage("bm-2", createdTime: 1700000000, from: Alice);

        string json = PackToJson(message);
        Assert.Contains("\"lang\":\"fi\"", json, "lang appears on the wire.");

        //Recovering Lang proves it was a TOP-LEVEL header: TryInterpret reads lang from the extension-header
        //bag (AdditionalHeaders), never from body, so a body-nested lang would recover as null.
        Assert.IsTrue(RoundTrip(message).TryInterpretBasicMessage(out BasicMessage? recovered));
        Assert.AreEqual("Hei maailma", recovered!.Content);
        Assert.AreEqual("fi", recovered.Lang, "lang round-trips as a top-level header, not a body member.");
    }


    [TestMethod]
    public void EmptyContentIsValidAndRoundTrips()
    {
        var basic = new BasicMessage { Content = "" };
        DidCommMessage message = basic.CreateBasicMessage("bm-3", createdTime: 1700000000, from: Alice);

        Assert.IsTrue(RoundTrip(message).TryInterpretBasicMessage(out BasicMessage? recovered));
        Assert.AreEqual("", recovered!.Content, "An empty content is a valid, if unusual, basic message.");
    }


    [TestMethod]
    public void DiscriminatorIsSemverAwareAndTypeDistinct()
    {
        var v21 = new DidCommMessage { Id = "m", Type = "https://didcomm.org/basicmessage/2.1/message" };
        Assert.IsTrue(v21.IsBasicMessage(), "A 2.1 basic message dispatches (same major version).");

        var v30 = new DidCommMessage { Id = "m", Type = "https://didcomm.org/basicmessage/3.0/message" };
        Assert.IsFalse(v30.IsBasicMessage(), "A 3.0 basic message is a different major version.");

        var other = new DidCommMessage { Id = "m", Type = "https://didcomm.org/trust-ping/2.0/ping" };
        Assert.IsFalse(other.IsBasicMessage());
    }


    [TestMethod]
    public void InterpretFailsClosed()
    {
        //Wrong type.
        Assert.IsFalse(Message("https://didcomm.org/trust-ping/2.0/ping", Dict((WellKnownBasicMessageNames.Content, "hi"))).TryInterpretBasicMessage(out _));

        //Missing body.
        Assert.IsFalse(Message(WellKnownBasicMessageNames.MessageType, body: null).TryInterpretBasicMessage(out _));

        //Missing content member.
        Assert.IsFalse(Message(WellKnownBasicMessageNames.MessageType, Dict()).TryInterpretBasicMessage(out _));

        //content is not a string.
        Assert.IsFalse(Message(WellKnownBasicMessageNames.MessageType, Dict((WellKnownBasicMessageNames.Content, 42))).TryInterpretBasicMessage(out _));

        //lang present but not a string.
        DidCommMessage withBadLang = Message(WellKnownBasicMessageNames.MessageType, Dict((WellKnownBasicMessageNames.Content, "hi")));
        withBadLang.AdditionalHeaders = new Dictionary<string, object> { [WellKnownBasicMessageNames.Lang] = 7 };
        Assert.IsFalse(withBadLang.TryInterpretBasicMessage(out _), "A non-string lang header is a malformation.");
    }


    [TestMethod]
    public void CreatedTimeIsRequiredAndAlwaysEmitted()
    {
        //Basic Message MUST carry the send time (didcomm.org/basicmessage/2.0 §message: "the time the message
        //is sent must be included"). created_time is a required CreateBasicMessage argument, so every basic
        //message round-trips a created_time.
        var basic = new BasicMessage { Content = "hi" };
        DidCommMessage message = basic.CreateBasicMessage("bm-time", createdTime: 1700000000, from: Alice);

        Assert.AreEqual(1700000000, RoundTrip(message).CreatedTime, "created_time MUST be present on every basic message.");
    }


    [TestMethod]
    public void BuildValidationThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new BasicMessage { Content = "hi" }.CreateBasicMessage("", 1700000000));
    }


    private static Dictionary<string, object> Dict(params (string Key, object? Value)[] members)
    {
        var dictionary = new Dictionary<string, object>();
        foreach((string key, object? value) in members)
        {
            dictionary[key] = value!;
        }

        return dictionary;
    }


    private static DidCommMessage Message(string type, Dictionary<string, object>? body) =>
        new() { Id = "message-id", Type = type, Body = body };


    private static DidCommMessage RoundTrip(DidCommMessage message)
    {
        using DidCommPlaintextMessage packed = message.PackPlaintext(DidCommMessageJson.Serializer, Pool);

        return packed.UnpackPlaintext(DidCommMessageJson.Parser);
    }


    private static string PackToJson(DidCommMessage message)
    {
        using DidCommPlaintextMessage packed = message.PackPlaintext(DidCommMessageJson.Serializer, Pool);

        return Encoding.UTF8.GetString(packed.AsReadOnlySpan());
    }
}
