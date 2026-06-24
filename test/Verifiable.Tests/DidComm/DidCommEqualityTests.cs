using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Verifiable.DidComm;
using Verifiable.DidComm.DiscoverFeatures;
using Verifiable.DidComm.ProblemReports;
using Verifiable.DidComm.Routing;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Value-equality tests for the DIDComm model types — the settable POCOs (<see cref="DidCommMessage"/>,
/// <see cref="Attachment"/>, <see cref="AttachmentData"/>) and the collection-bearing records — and for the
/// shared <see cref="StructuralEquality"/> primitives that back them. Two messages built independently with the
/// same content (including a nested arbitrary-JSON <c>body</c>) MUST be equal, and a firewalled wire round trip
/// MUST reconstruct an equal message.
/// </summary>
[TestClass]
internal sealed class DidCommEqualityTests
{
    /// <summary>The test context, for cancellation and diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The pooled-memory source for pack/unpack.</summary>
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// Builds a fully-populated message whose every member is structurally re-created on each call (fresh
    /// dictionaries, lists and nested graphs), so two calls produce distinct instances that MUST compare equal.
    /// Restricted to members proven to survive the plaintext round trip, so the same sample drives both the
    /// model-equality and the wire round-trip assertions.
    /// </summary>
    /// <returns>A new, fully-populated <see cref="DidCommMessage"/>.</returns>
    private static DidCommMessage BuildSampleMessage() => new()
    {
        Id = "msg-1",
        Type = "https://example.com/protocols/x/1.0/proposal",
        From = "did:example:alice",
        To = ["did:example:bob", "did:example:carol"],
        ThreadId = "thread-1",
        ParentThreadId = "parent-1",
        CreatedTime = 1516269022,
        ExpiresTime = 1516385931,
        FromPrior = "<from-prior-jwt>",
        Body = new Dictionary<string, object>
        {
            ["attribute"] = "and its value",
            ["count"] = 42,
            ["nested"] = new Dictionary<string, object>
            {
                ["key"] = "value",
                ["list"] = new List<object> { 1, "two", true }
            }
        },
        Attachments =
        [
            new Attachment
            {
                Id = "a1",
                Description = "an attachment",
                MediaType = "application/json",
                Data = new AttachmentData { Base64 = "WW91ciBob3ZlcmNyYWZ0IGlzIGZ1bGwgb2YgZWVscw==" }
            }
        ],
        AdditionalHeaders = new Dictionary<string, object> { ["custom_header"] = "extension value" }
    };


    /// <summary>Two independently-built messages with identical content are equal by <c>Equals</c>, <c>==</c>, and hash code.</summary>
    [TestMethod]
    public void IdenticalMessagesAreValueEqual()
    {
        DidCommMessage a = BuildSampleMessage();
        DidCommMessage b = BuildSampleMessage();

        Assert.AreEqual(a, b);
        Assert.IsTrue(a == b);
        Assert.IsFalse(a != b);
        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
    }


    /// <summary>A difference in a scalar header breaks equality.</summary>
    [TestMethod]
    public void MessageDifferingInScalarIsNotEqual()
    {
        DidCommMessage a = BuildSampleMessage();
        DidCommMessage b = BuildSampleMessage();
        b.Id = "msg-2";

        Assert.AreNotEqual(a, b);
        Assert.IsTrue(a != b);
    }


    /// <summary>A difference deep inside the arbitrary-JSON <c>body</c> graph breaks equality (proves the body is deep-compared).</summary>
    [TestMethod]
    public void MessageDifferingInNestedBodyValueIsNotEqual()
    {
        DidCommMessage a = BuildSampleMessage();
        DidCommMessage b = BuildSampleMessage();
        ((Dictionary<string, object>)b.Body!["nested"])["key"] = "CHANGED";

        Assert.AreNotEqual(a, b);
    }


    /// <summary>Two bodies with the same entries in a different key order are equal — dictionary comparison is order-independent.</summary>
    [TestMethod]
    public void MessageWithReorderedBodyKeysIsEqual()
    {
        DidCommMessage a = BuildSampleMessage();
        DidCommMessage b = BuildSampleMessage();
        b.Body = new Dictionary<string, object>
        {
            ["nested"] = new Dictionary<string, object>
            {
                ["list"] = new List<object> { 1, "two", true },
                ["key"] = "value"
            },
            ["count"] = 42,
            ["attribute"] = "and its value"
        };

        Assert.AreEqual(a, b);
        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
    }


    /// <summary>The typed id lists compare in order: reordering <c>To</c> breaks equality.</summary>
    [TestMethod]
    public void MessageWithReorderedToListIsNotEqual()
    {
        DidCommMessage a = BuildSampleMessage();
        DidCommMessage b = BuildSampleMessage();
        b.To = ["did:example:carol", "did:example:bob"];

        Assert.AreNotEqual(a, b);
    }


    /// <summary>
    /// A firewalled round trip — pack to <c>application/didcomm-plain+json</c> bytes, then reconstruct purely from
    /// those bytes — yields a message value-equal to the original, and the two serialize to deep-equal JSON.
    /// </summary>
    [TestMethod]
    public void RoundTripThroughWireIsEqualToOriginal()
    {
        DidCommMessage original = BuildSampleMessage();

        using DidCommPlaintextMessage packed = original.PackPlaintext(DidCommMessageJson.Serializer, Pool);
        DidCommMessage roundTripped = packed.UnpackPlaintext(DidCommMessageJson.Parser);

        Assert.AreEqual(original, roundTripped);
        Assert.AreEqual(original.GetHashCode(), roundTripped.GetHashCode());

        //Cross-check against the established STJ deep comparer: equal models serialize to deep-equal JSON.
        using DidCommPlaintextMessage packedAgain = BuildSampleMessage().PackPlaintext(DidCommMessageJson.Serializer, Pool);
        string firstJson = Encoding.UTF8.GetString(packed.AsReadOnlyMemory().Span);
        string secondJson = Encoding.UTF8.GetString(packedAgain.AsReadOnlyMemory().Span);
        Assert.IsTrue(JsonSerializationUtilities.CompareJsonElements(firstJson, secondJson));
    }


    /// <summary>The typed collection members <c>To</c>/<c>PleaseAck</c>/<c>Ack</c> participate in equality element-wise.</summary>
    [TestMethod]
    public void MessageCollectionMembersParticipateInEquality()
    {
        var a = new DidCommMessage { Id = "m", To = ["x"], PleaseAck = ["p1"], Ack = ["a0"] };
        var b = new DidCommMessage { Id = "m", To = ["x"], PleaseAck = ["p1"], Ack = ["a0"] };
        Assert.AreEqual(a, b);

        var c = new DidCommMessage { Id = "m", To = ["x"], PleaseAck = ["p1"], Ack = ["a1"] };
        Assert.AreNotEqual(a, c);
    }


    /// <summary>Attachment data deep-compares its opaque-JSON <c>json</c>/<c>jws</c> members and sequences its <c>links</c>.</summary>
    [TestMethod]
    public void AttachmentDataDeepComparesOpaqueJson()
    {
        var a = new AttachmentData
        {
            Hash = "<hash>",
            Links = ["https://a", "https://b"],
            Json = new Dictionary<string, object> { ["k"] = new List<object> { 1, 2 } }
        };
        var b = new AttachmentData
        {
            Hash = "<hash>",
            Links = ["https://a", "https://b"],
            Json = new Dictionary<string, object> { ["k"] = new List<object> { 1, 2 } }
        };
        Assert.AreEqual(a, b);
        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());

        var c = new AttachmentData
        {
            Hash = "<hash>",
            Links = ["https://a", "https://b"],
            Json = new Dictionary<string, object> { ["k"] = new List<object> { 1, 3 } }
        };
        Assert.AreNotEqual(a, c);
    }


    /// <summary>A resolved delivery target and a service endpoint sequence-compare their <c>Accept</c>/<c>RoutingKeys</c>.</summary>
    [TestMethod]
    public void RoutingRecordsSequenceCompareCollections()
    {
        var endpointA = new DidCommServiceEndpoint { Uri = "https://e", Accept = ["didcomm/v2"], RoutingKeys = ["did:k#1"] };
        var endpointB = new DidCommServiceEndpoint { Uri = "https://e", Accept = ["didcomm/v2"], RoutingKeys = ["did:k#1"] };
        Assert.AreEqual(endpointA, endpointB);
        Assert.AreEqual(endpointA.GetHashCode(), endpointB.GetHashCode());

        var endpointC = endpointB with { RoutingKeys = ["did:k#2"] };
        Assert.AreNotEqual(endpointA, endpointC);

        var targetA = new DidCommDeliveryTarget { TransportUri = "https://t", RoutingKeys = ["did:k#1"] };
        var targetB = new DidCommDeliveryTarget { TransportUri = "https://t", RoutingKeys = ["did:k#1"] };
        Assert.AreEqual(targetA, targetB);
    }


    /// <summary>A problem report sequence-compares its <c>Args</c> (which permit null elements) and <c>Ack</c>.</summary>
    [TestMethod]
    public void ProblemReportSequenceComparesArgs()
    {
        var a = new ProblemReport { Code = ProblemCode.Parse("e.p.xfer.cant-use-endpoint"), ParentThreadId = "t", Args = ["one", null], Ack = ["m0"] };
        var b = new ProblemReport { Code = ProblemCode.Parse("e.p.xfer.cant-use-endpoint"), ParentThreadId = "t", Args = ["one", null], Ack = ["m0"] };
        Assert.AreEqual(a, b);
        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());

        var c = a with { Args = ["one", "two"] };
        Assert.AreNotEqual(a, c);
    }


    /// <summary>A feature disclosure sequence-compares its <c>Roles</c> and deep-compares its arbitrary-JSON <c>AdditionalFields</c>.</summary>
    [TestMethod]
    public void DiscoverFeaturesDiscloseDeepEquality()
    {
        var a = new DiscoverFeaturesDisclose
        {
            Disclosures =
            [
                new FeatureDisclosure
                {
                    FeatureType = "protocol",
                    Id = "https://didcomm.org/tictactoe/1.0",
                    Roles = ["player"],
                    AdditionalFields = new Dictionary<string, object> { ["max_receive_bytes"] = 1000 }
                }
            ]
        };
        var b = new DiscoverFeaturesDisclose
        {
            Disclosures =
            [
                new FeatureDisclosure
                {
                    FeatureType = "protocol",
                    Id = "https://didcomm.org/tictactoe/1.0",
                    Roles = ["player"],
                    AdditionalFields = new Dictionary<string, object> { ["max_receive_bytes"] = 1000 }
                }
            ]
        };
        Assert.AreEqual(a, b);
        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());

        var c = b with
        {
            Disclosures =
            [
                new FeatureDisclosure
                {
                    FeatureType = "protocol",
                    Id = "https://didcomm.org/tictactoe/1.0",
                    Roles = ["player"],
                    AdditionalFields = new Dictionary<string, object> { ["max_receive_bytes"] = 2000 }
                }
            ]
        };
        Assert.AreNotEqual(a, c);
    }


    /// <summary><see cref="StructuralEquality.JsonEqual"/> is key-order-independent for objects, order-sensitive for arrays, and CLR-type-sensitive for number scalars.</summary>
    [TestMethod]
    public void JsonEqualSemantics()
    {
        var left = new Dictionary<string, object> { ["a"] = 1, ["b"] = new List<object> { "x", "y" } };
        var rightSameOrderless = new Dictionary<string, object> { ["b"] = new List<object> { "x", "y" }, ["a"] = 1 };
        var rightReorderedList = new Dictionary<string, object> { ["a"] = 1, ["b"] = new List<object> { "y", "x" } };

        Assert.IsTrue(StructuralEquality.JsonEqual(left, rightSameOrderless));
        Assert.IsFalse(StructuralEquality.JsonEqual(left, rightReorderedList));

        //A number's CLR type is part of its identity: an int 42 is not the long 42 (they never share a wire token).
        Assert.IsFalse(StructuralEquality.JsonEqual(42, 42L));
        Assert.IsTrue(StructuralEquality.JsonEqual(42, 42));

        //Null handling.
        Assert.IsTrue(StructuralEquality.JsonEqual(null, null));
        Assert.IsFalse(StructuralEquality.JsonEqual(null, 1));
    }


    /// <summary><see cref="StructuralEquality.SequenceEqual"/> treats two nulls as equal and a null as unequal to a non-null sequence.</summary>
    [TestMethod]
    public void SequenceEqualNullHandling()
    {
        Assert.IsTrue(StructuralEquality.SequenceEqual<string>(null, null));
        Assert.IsFalse(StructuralEquality.SequenceEqual(null, new List<string> { "a" }));
        Assert.IsTrue(StructuralEquality.SequenceEqual(new List<string> { "a" }, new List<string> { "a" }));
        Assert.IsFalse(StructuralEquality.SequenceEqual(new List<string> { "a" }, new List<string> { "b" }));
    }
}
