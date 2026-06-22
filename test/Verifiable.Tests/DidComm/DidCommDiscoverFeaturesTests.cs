using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Verifiable.DidComm;
using Verifiable.Foundation;
using Verifiable.Json;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// Tests for the DIDComm v2.1 Discover Features Protocol 2.0 (<see cref="DiscoverFeaturesExtensions"/>): the
/// <c>query</c>/<c>disclose</c> build + interpret round trips, the disclose thread continuation, the sparse-response
/// semantics (missing roles, empty disclosures), and the responder <see cref="DiscoverFeaturesExtensions.MatchDisclosures"/>
/// behavior — the three recognized feature types, the <c>*</c> wildcard, the MUST-ignore-unrecognized rule, and
/// de-duplication — plus the fail-closed interpret batteries.
/// </summary>
[TestClass]
internal sealed class DidCommDiscoverFeaturesTests
{
    private static readonly MemoryPool<byte> Pool = BaseMemoryPool.Shared;

    private const string Alice = "did:example:alice";
    private const string TicTacToe10 = "https://didcomm.org/tictactoe/1.0";
    private const string TicTacToeWildcard = "https://didcomm.org/tictactoe/1.*";


    [TestMethod]
    public void QueryRoundTrips()
    {
        var query = new DiscoverFeaturesQuery
        {
            Queries =
            [
                new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Match = TicTacToeWildcard },
                new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.GoalCode, Match = "org.didcomm.*" }
            ]
        };

        DidCommMessage message = query.CreateDiscoverFeaturesQuery("query-1", from: Alice);

        Assert.IsTrue(message.IsDiscoverFeaturesQuery());
        Assert.AreEqual(WellKnownDiscoverFeaturesNames.QueryType, message.Type);

        string json = PackToJson(message);
        Assert.Contains("discover-features/2.0/queries", json, "The query type URI is the plural 'queries'.");
        Assert.Contains("\"feature-type\":\"protocol\"", json, "feature-type sits in a query descriptor.");
        Assert.Contains("\"match\":\"https://didcomm.org/tictactoe/1.*\"", json, "The match (with its wildcard) is preserved verbatim.");

        Assert.IsTrue(RoundTrip(message).TryInterpretDiscoverFeaturesQuery(out DiscoverFeaturesQuery? recovered));
        Assert.HasCount(2, recovered!.Queries);
        Assert.AreEqual(WellKnownDiscoverFeaturesNames.Protocol, recovered.Queries[0].FeatureType);
        Assert.AreEqual(TicTacToeWildcard, recovered.Queries[0].Match);
        Assert.AreEqual(WellKnownDiscoverFeaturesNames.GoalCode, recovered.Queries[1].FeatureType);
        Assert.AreEqual("org.didcomm.*", recovered.Queries[1].Match);
    }


    [TestMethod]
    public void DiscloseRoundTripsAndContinuesQueryThread()
    {
        var disclose = new DiscoverFeaturesDisclose
        {
            Disclosures =
            [
                new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Id = TicTacToe10, Roles = ["player"] },
                new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.GoalCode, Id = "org.didcomm.sell.goods.consumer" }
            ]
        };

        DidCommMessage message = disclose.CreateDiscoverFeaturesDisclose("disclose-1", threadId: "query-1", from: Alice);

        Assert.IsTrue(message.IsDiscoverFeaturesDisclose());
        Assert.AreEqual(WellKnownDiscoverFeaturesNames.DiscloseType, message.Type);
        Assert.AreEqual("query-1", message.ThreadId, "A disclose MUST continue the query's thread (thid echoes the query id).");

        string json = PackToJson(message);
        Assert.Contains("discover-features/2.0/disclose", json, "The disclose type URI.");
        Assert.Contains("\"thid\":\"query-1\"", json, "The disclose thid echoes the query id.");
        Assert.Contains("\"id\":\"https://didcomm.org/tictactoe/1.0\"", json, "The disclosure id is the protocol PIURI.");
        Assert.Contains("\"roles\":[\"player\"]", json, "Protocol roles are disclosed as an array.");

        DidCommMessage parsed = RoundTrip(message);
        Assert.AreEqual("query-1", parsed.ThreadId);
        Assert.IsTrue(parsed.TryInterpretDiscoverFeaturesDisclose(out DiscoverFeaturesDisclose? recovered));
        Assert.HasCount(2, recovered!.Disclosures);
        Assert.AreEqual(TicTacToe10, recovered.Disclosures[0].Id);
        Assert.IsNotNull(recovered.Disclosures[0].Roles);
        Assert.AreEqual("player", recovered.Disclosures[0].Roles![0]);
        Assert.IsNull(recovered.Disclosures[1].Roles, "A disclosure without roles recovers null roles.");
    }


    [TestMethod]
    public void ConstraintDisclosureExtraFieldRoundTrips()
    {
        //The spec's §Agent Constraint Disclosure: a 'constraint' descriptor carrying its own value member
        //(max_receive_bytes) beyond feature-type/id — preserved verbatim via AdditionalFields.
        var disclose = new DiscoverFeaturesDisclose
        {
            Disclosures =
            [
                new FeatureDisclosure
                {
                    FeatureType = "constraint",
                    Id = "max_receive_bytes",
                    AdditionalFields = new Dictionary<string, object> { ["max_receive_bytes"] = "65536" }
                }
            ]
        };

        DidCommMessage message = disclose.CreateDiscoverFeaturesDisclose("disclose-constraint", threadId: "q-1");
        string json = PackToJson(message);
        Assert.Contains("\"max_receive_bytes\":\"65536\"", json, "The extra constraint field is carried on the wire verbatim.");

        Assert.IsTrue(RoundTrip(message).TryInterpretDiscoverFeaturesDisclose(out DiscoverFeaturesDisclose? recovered));
        Assert.IsNotNull(recovered!.Disclosures[0].AdditionalFields);
        Assert.AreEqual("65536", recovered.Disclosures[0].AdditionalFields!["max_receive_bytes"].ToString());
    }


    [TestMethod]
    public void DiscloseWithoutRolesOmitsRolesAndRecoversNull()
    {
        var disclose = new DiscoverFeaturesDisclose
        {
            Disclosures = [new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Id = TicTacToe10 }]
        };

        DidCommMessage message = disclose.CreateDiscoverFeaturesDisclose("disclose-2", threadId: "query-1");
        string json = PackToJson(message);

        Assert.DoesNotContain("\"roles\"", json, "A null roles is not emitted (a missing roles is not 'no roles').");

        Assert.IsTrue(RoundTrip(message).TryInterpretDiscoverFeaturesDisclose(out DiscoverFeaturesDisclose? recovered));
        Assert.IsNull(recovered!.Disclosures[0].Roles);
    }


    [TestMethod]
    public void EmptyDisclosuresIsValidAndRoundTrips()
    {
        //A sparse, empty disclosures array is NOT "I support no matching features" (DIDComm v2.1 §Sparse Responses).
        var disclose = new DiscoverFeaturesDisclose { Disclosures = [] };

        DidCommMessage message = disclose.CreateDiscoverFeaturesDisclose("disclose-3", threadId: "query-1");

        Assert.IsTrue(RoundTrip(message).TryInterpretDiscoverFeaturesDisclose(out DiscoverFeaturesDisclose? recovered));
        Assert.IsEmpty(recovered!.Disclosures);
    }


    [TestMethod]
    public void ProactiveDiscloseHasNoThreadAndStillInterprets()
    {
        var disclose = new DiscoverFeaturesDisclose
        {
            Disclosures = [new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Id = TicTacToe10 }]
        };

        DidCommMessage message = disclose.CreateDiscoverFeaturesDisclose("disclose-4", threadId: null);
        Assert.IsNull(message.ThreadId, "A proactive (unsolicited) disclosure carries no thid.");

        DidCommMessage parsed = RoundTrip(message);
        Assert.IsNull(parsed.ThreadId);
        Assert.IsTrue(parsed.TryInterpretDiscoverFeaturesDisclose(out DiscoverFeaturesDisclose? recovered), "A thid-less proactive disclose still interprets.");
        Assert.HasCount(1, recovered!.Disclosures);
    }


    [TestMethod]
    public void MatchRecognizesProtocolGoalCodeAndHeader()
    {
        //Implementations MUST recognize protocol, goal-code, and header (DIDComm v2.1 §Discover Features Protocol 2.0).
        IReadOnlyList<FeatureDisclosure> catalog =
        [
            new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Id = TicTacToe10, Roles = ["player"] },
            new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.GoalCode, Id = "org.didcomm.sell.goods.consumer" },
            new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Header, Id = "my-custom-header" }
        ];

        var query = new DiscoverFeaturesQuery
        {
            Queries =
            [
                new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Match = TicTacToeWildcard },
                new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.GoalCode, Match = "org.didcomm.*" },
                new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.Header, Match = "my-custom-header" }
            ]
        };

        DiscoverFeaturesDisclose disclose = query.MatchDisclosures(catalog);

        Assert.HasCount(3, disclose.Disclosures);
        HashSet<string> disclosedTypes = disclose.Disclosures.Select(d => d.FeatureType).ToHashSet();
        Assert.Contains(WellKnownDiscoverFeaturesNames.Protocol, disclosedTypes);
        Assert.Contains(WellKnownDiscoverFeaturesNames.GoalCode, disclosedTypes);
        Assert.Contains(WellKnownDiscoverFeaturesNames.Header, disclosedTypes);
        Assert.AreEqual(TicTacToe10, disclose.Disclosures.Single(d => d.FeatureType == WellKnownDiscoverFeaturesNames.Protocol).Id, "The matched protocol carries its PIURI.");
    }


    [DataRow(TicTacToeWildcard, TicTacToe10, true)]
    [DataRow(TicTacToeWildcard, "https://didcomm.org/tictactoe/2.0", false)]
    [DataRow("*", "anything-you-want-to-share", true)]
    [DataRow(TicTacToe10, TicTacToe10, true)]
    [DataRow(TicTacToe10, "https://didcomm.org/tictactoe/1.1", false)]
    [DataRow("https://didcomm.org/*/1.0", "https://didcomm.org/tictactoe/1.0", false)]
    [TestMethod]
    public void MatchWildcardSemantics(string match, string candidate, bool expectMatch)
    {
        var query = new DiscoverFeaturesQuery
        {
            Queries = [new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Match = match }]
        };
        IReadOnlyList<FeatureDisclosure> catalog =
            [new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Id = candidate }];

        DiscoverFeaturesDisclose disclose = query.MatchDisclosures(catalog);

        Assert.AreEqual(expectMatch, disclose.Disclosures.Count == 1, $"match '{match}' vs '{candidate}' expected match={expectMatch}.");
    }


    [TestMethod]
    public void MatchIgnoresUnrecognizedFeatureType()
    {
        //An unrecognized feature-type MUST be ignored, NOT error (DIDComm v2.1 §Discover Features Protocol 2.0):
        //the unrecognized descriptor's bare '*' must NOT pull in the goal-code entry, while the protocol query still matches.
        IReadOnlyList<FeatureDisclosure> catalog =
        [
            new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Id = TicTacToe10 },
            new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.GoalCode, Id = "org.didcomm.sell" }
        ];

        var query = new DiscoverFeaturesQuery
        {
            Queries =
            [
                new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Match = "*" },
                new FeatureQuery { FeatureType = "x-totally-unrecognized-type", Match = "*" }
            ]
        };

        DiscoverFeaturesDisclose disclose = query.MatchDisclosures(catalog);

        Assert.HasCount(1, disclose.Disclosures);
        Assert.AreEqual(TicTacToe10, disclose.Disclosures[0].Id, "Only the recognized protocol query matched; the unrecognized feature-type matched nothing and did not error.");
    }


    [TestMethod]
    public void MatchDeduplicatesAndAnEmptyMatchIsSparse()
    {
        IReadOnlyList<FeatureDisclosure> catalog =
            [new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Id = TicTacToe10 }];

        //Two overlapping descriptors match the same feature; it is disclosed once.
        var overlapping = new DiscoverFeaturesQuery
        {
            Queries =
            [
                new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Match = "*" },
                new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Match = TicTacToeWildcard }
            ]
        };
        Assert.HasCount(1, overlapping.MatchDisclosures(catalog).Disclosures, "An entry matched by two descriptors is disclosed once.");

        //No match yields an empty (valid) disclosure, not an error.
        var noMatch = new DiscoverFeaturesQuery
        {
            Queries = [new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Match = "https://didcomm.org/nonesuch/9.*" }]
        };
        Assert.IsEmpty(noMatch.MatchDisclosures(catalog).Disclosures);
    }


    [TestMethod]
    public void QueryInterpretFailsClosed()
    {
        //Wrong type.
        Assert.IsFalse(Message(WellKnownDiscoverFeaturesNames.DiscloseType, Dict((WellKnownDiscoverFeaturesNames.Queries, OneQueryDescriptor()))).TryInterpretDiscoverFeaturesQuery(out _));

        //Missing body.
        Assert.IsFalse(Message(WellKnownDiscoverFeaturesNames.QueryType, body: null).TryInterpretDiscoverFeaturesQuery(out _));

        //Missing queries member.
        Assert.IsFalse(Message(WellKnownDiscoverFeaturesNames.QueryType, Dict()).TryInterpretDiscoverFeaturesQuery(out _));

        //queries is not an array (a string).
        Assert.IsFalse(QueryWith("not-an-array").TryInterpretDiscoverFeaturesQuery(out _));

        //queries is an empty array (MUST be one or more).
        Assert.IsFalse(QueryWith(new List<object>()).TryInterpretDiscoverFeaturesQuery(out _));

        //A descriptor is not a JSON object.
        Assert.IsFalse(QueryWith(new List<object> { "not-an-object" }).TryInterpretDiscoverFeaturesQuery(out _));

        //A descriptor is missing match.
        Assert.IsFalse(QueryWith(new List<object> { Dict((WellKnownDiscoverFeaturesNames.FeatureType, "protocol")) }).TryInterpretDiscoverFeaturesQuery(out _));

        //A descriptor is missing feature-type.
        Assert.IsFalse(QueryWith(new List<object> { Dict((WellKnownDiscoverFeaturesNames.Match, "*")) }).TryInterpretDiscoverFeaturesQuery(out _));

        //A descriptor's match is not a string.
        Assert.IsFalse(QueryWith(new List<object> { Dict((WellKnownDiscoverFeaturesNames.FeatureType, "protocol"), (WellKnownDiscoverFeaturesNames.Match, 42)) }).TryInterpretDiscoverFeaturesQuery(out _));
    }


    [TestMethod]
    public void DiscloseInterpretFailsClosed()
    {
        //Wrong type.
        Assert.IsFalse(Message(WellKnownDiscoverFeaturesNames.QueryType, Dict((WellKnownDiscoverFeaturesNames.Disclosures, new List<object>()))).TryInterpretDiscoverFeaturesDisclose(out _));

        //Missing body.
        Assert.IsFalse(Message(WellKnownDiscoverFeaturesNames.DiscloseType, body: null).TryInterpretDiscoverFeaturesDisclose(out _));

        //Missing disclosures member.
        Assert.IsFalse(Message(WellKnownDiscoverFeaturesNames.DiscloseType, Dict()).TryInterpretDiscoverFeaturesDisclose(out _));

        //disclosures is not an array.
        Assert.IsFalse(DiscloseWith("not-an-array").TryInterpretDiscoverFeaturesDisclose(out _));

        //A descriptor is not a JSON object.
        Assert.IsFalse(DiscloseWith(new List<object> { "not-an-object" }).TryInterpretDiscoverFeaturesDisclose(out _));

        //A descriptor is missing id.
        Assert.IsFalse(DiscloseWith(new List<object> { Dict((WellKnownDiscoverFeaturesNames.FeatureType, "protocol")) }).TryInterpretDiscoverFeaturesDisclose(out _));

        //A descriptor is missing feature-type.
        Assert.IsFalse(DiscloseWith(new List<object> { Dict((WellKnownDiscoverFeaturesNames.Id, TicTacToe10)) }).TryInterpretDiscoverFeaturesDisclose(out _));

        //roles is present but not an array.
        Assert.IsFalse(DiscloseWith(new List<object> { Dict((WellKnownDiscoverFeaturesNames.FeatureType, "protocol"), (WellKnownDiscoverFeaturesNames.Id, TicTacToe10), (WellKnownDiscoverFeaturesNames.Roles, "player")) }).TryInterpretDiscoverFeaturesDisclose(out _));

        //roles holds a non-string element.
        Assert.IsFalse(DiscloseWith(new List<object> { Dict((WellKnownDiscoverFeaturesNames.FeatureType, "protocol"), (WellKnownDiscoverFeaturesNames.Id, TicTacToe10), (WellKnownDiscoverFeaturesNames.Roles, new List<object> { 7 })) }).TryInterpretDiscoverFeaturesDisclose(out _));
    }


    [TestMethod]
    public void ResponderFlowMatchesAndThreadsBackToQuery()
    {
        //The whole responder chain: receive a query, match it against the catalog, and reply on the query's thread.
        var query = new DiscoverFeaturesQuery
        {
            Queries = [new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Match = TicTacToeWildcard }]
        };
        DidCommMessage queryMessage = query.CreateDiscoverFeaturesQuery("q-1", from: Alice);

        Assert.IsTrue(RoundTrip(queryMessage).TryInterpretDiscoverFeaturesQuery(out DiscoverFeaturesQuery? received));
        IReadOnlyList<FeatureDisclosure> catalog =
            [new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Id = TicTacToe10, Roles = ["player"] }];

        DiscoverFeaturesDisclose matched = received!.MatchDisclosures(catalog);
        DidCommMessage discloseMessage = matched.CreateDiscoverFeaturesDisclose("d-1", threadId: queryMessage.Id);

        DidCommMessage parsed = RoundTrip(discloseMessage);
        Assert.AreEqual("q-1", parsed.ThreadId, "The responder's disclose continues the query's thread.");
        Assert.IsTrue(parsed.TryInterpretDiscoverFeaturesDisclose(out DiscoverFeaturesDisclose? recovered));
        Assert.HasCount(1, recovered!.Disclosures);
        Assert.AreEqual(TicTacToe10, recovered.Disclosures[0].Id);
    }


    [TestMethod]
    public void NonProtocolRolesAreCarriedVerbatim()
    {
        //The spec scopes roles to protocols permissively ("may"); the library reads/writes roles verbatim for any
        //feature-type (a faithful wire read), neither emitting nor rejecting based on type.
        var disclose = new DiscoverFeaturesDisclose
        {
            Disclosures = [new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.GoalCode, Id = "org.didcomm.sell", Roles = ["seller"] }]
        };

        DidCommMessage message = disclose.CreateDiscoverFeaturesDisclose("disclose-5", threadId: "q-1");

        Assert.IsTrue(RoundTrip(message).TryInterpretDiscoverFeaturesDisclose(out DiscoverFeaturesDisclose? recovered));
        Assert.AreEqual(WellKnownDiscoverFeaturesNames.GoalCode, recovered!.Disclosures[0].FeatureType);
        Assert.IsNotNull(recovered.Disclosures[0].Roles);
        Assert.AreEqual("seller", recovered.Disclosures[0].Roles![0]);
    }


    [TestMethod]
    public void CatalogDuplicateIdIsDisclosedOnceFirstWins()
    {
        //A catalog holding two entries with the same (feature-type, id) is degenerate (the spec says id "unambiguously
        //identifies a single item"); the matcher dedups by (feature-type, id), keeping the FIRST in catalog order.
        IReadOnlyList<FeatureDisclosure> catalog =
        [
            new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Id = TicTacToe10, Roles = ["player"] },
            new FeatureDisclosure { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Id = TicTacToe10, Roles = ["observer"] }
        ];
        var query = new DiscoverFeaturesQuery
        {
            Queries = [new FeatureQuery { FeatureType = WellKnownDiscoverFeaturesNames.Protocol, Match = "*" }]
        };

        DiscoverFeaturesDisclose disclose = query.MatchDisclosures(catalog);

        Assert.HasCount(1, disclose.Disclosures);
        Assert.AreEqual("player", disclose.Disclosures[0].Roles![0], "The first catalog entry wins the dedup.");
    }


    [TestMethod]
    public void BuildValidationThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new DiscoverFeaturesQuery { Queries = [] }.CreateDiscoverFeaturesQuery("id"));
        Assert.ThrowsExactly<ArgumentException>(() =>
            new DiscoverFeaturesQuery { Queries = [new FeatureQuery { FeatureType = "protocol", Match = "*" }] }.CreateDiscoverFeaturesQuery(""));
        Assert.ThrowsExactly<ArgumentException>(() =>
            new DiscoverFeaturesDisclose { Disclosures = [] }.CreateDiscoverFeaturesDisclose("", threadId: "t"));
    }


    private static List<object> OneQueryDescriptor() =>
        [Dict((WellKnownDiscoverFeaturesNames.FeatureType, "protocol"), (WellKnownDiscoverFeaturesNames.Match, "*"))];


    private static DidCommMessage QueryWith(object queriesValue) =>
        Message(WellKnownDiscoverFeaturesNames.QueryType, Dict((WellKnownDiscoverFeaturesNames.Queries, queriesValue)));


    private static DidCommMessage DiscloseWith(object disclosuresValue) =>
        Message(WellKnownDiscoverFeaturesNames.DiscloseType, Dict((WellKnownDiscoverFeaturesNames.Disclosures, disclosuresValue)));


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
