using System.Linq;
using System.Text.Json;
using CsCheck;
using Verifiable.Core.SecurityEvents;
using Verifiable.Json;
using Verifiable.OAuth.Ssf;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Property tests for the Shared Signals transmitter JSON writers
/// (<see cref="SsfTransmitterJsonWriting"/>): for arbitrary values — including
/// strings full of quotes, backslashes, control characters, JSON separators,
/// and non-ASCII — transmitter emission followed by the RECEIVER's strict
/// parsing must be an exact inverse round trip. This pins the two halves of the
/// wire contract (hand-built <c>JsonAppender</c> writing versus
/// <c>Verifiable.Json</c> parsing) to each other.
/// </summary>
[TestClass]
internal sealed class SsfJsonWritingPropertyTests
{
    public TestContext TestContext { get; set; } = null!;

    //Characters that hammer the JSON escaping paths: quotes, backslashes,
    //control characters, separators, and non-ASCII. Lone surrogates are
    //excluded — they cannot appear in well-formed UTF-16 input strings.
    private static readonly Gen<char> JsonCharGen = Gen.OneOf(
        Gen.Char['a', 'z'],
        Gen.Char['0', '9'],
        Gen.Char['\u0001', '\u001F'],
        Gen.Const('"'),
        Gen.Const('\\'),
        Gen.Const('/'),
        Gen.Const(' '),
        Gen.Const(','),
        Gen.Const(':'),
        Gen.Const('{'),
        Gen.Const('}'),
        Gen.Const('['),
        Gen.Const(']'),
        Gen.Const('ä'),
        Gen.Const('€'),
        Gen.Const(' '));

    private static readonly Gen<string> JsonStringGen =
        JsonCharGen.Array[1, 12].Select(static chars => new string(chars));

    private static readonly Gen<IReadOnlyList<string>> StringListGen =
        JsonStringGen.Array[1, 4].Select(static items => (IReadOnlyList<string>)items);

    private static readonly Gen<int?> OptionalIntGen =
        Gen.OneOf(Gen.Const((int?)null), Gen.Int.Select(static i => (int?)i));

    private static readonly Gen<SsfDeliveryConfiguration> DeliveryGen =
        from method in JsonStringGen
        from endpointUrl in GenOption(JsonStringGen)
        from authorizationHeader in GenOption(JsonStringGen)
        select new SsfDeliveryConfiguration
        {
            Method = method,
            EndpointUrl = endpointUrl,
            AuthorizationHeader = authorizationHeader
        };

    private static readonly Gen<SsfStreamConfiguration> StreamGen =
        from streamId in JsonStringGen
        from issuer in JsonStringGen
        from audiences in StringListGen
        from delivery in DeliveryGen
        from supported in GenOption(StringListGen)
        from requested in GenOption(StringListGen)
        from delivered in GenOption(StringListGen)
        from minInterval in OptionalIntGen
        from description in GenOption(JsonStringGen)
        from inactivity in OptionalIntGen
        select new SsfStreamConfiguration
        {
            StreamId = streamId,
            Issuer = issuer,
            Audiences = audiences,
            Delivery = delivery,
            EventsSupported = supported,
            EventsRequested = requested,
            EventsDelivered = delivered,
            MinVerificationInterval = minInterval,
            Description = description,
            InactivityTimeout = inactivity
        };


    [TestMethod]
    public void StreamConfigurationWriteThenStrictParseRoundTrips()
    {
        StreamGen.Sample(stream =>
        {
            string json = SsfTransmitterJsonWriting.BuildStreamConfigurationJson(stream);
            SsfStreamConfiguration? parsed = SsfStreamJsonParsing.ParseStreamConfiguration(json);

            Assert.IsNotNull(parsed, $"The emitted configuration must strict-parse. Json: {json}");
            Assert.AreEqual(stream.StreamId, parsed.StreamId);
            Assert.AreEqual(stream.Issuer, parsed.Issuer);
            Assert.IsTrue(stream.Audiences.SequenceEqual(parsed.Audiences, StringComparer.Ordinal));
            Assert.AreEqual(stream.Delivery.Method, parsed.Delivery.Method);
            Assert.AreEqual(stream.Delivery.EndpointUrl, parsed.Delivery.EndpointUrl);
            Assert.AreEqual(stream.Delivery.AuthorizationHeader, parsed.Delivery.AuthorizationHeader);
            AssertListsEqual(stream.EventsSupported, parsed.EventsSupported);
            AssertListsEqual(stream.EventsRequested, parsed.EventsRequested);
            AssertListsEqual(stream.EventsDelivered, parsed.EventsDelivered);
            Assert.AreEqual(stream.MinVerificationInterval, parsed.MinVerificationInterval);
            Assert.AreEqual(stream.Description, parsed.Description);
            Assert.AreEqual(stream.InactivityTimeout, parsed.InactivityTimeout);
        });
    }


    [TestMethod]
    public void StreamConfigurationArrayIsWellFormedAndElementsRoundTrip()
    {
        StreamGen.Array[0, 3].Sample(streams =>
        {
            string json = SsfTransmitterJsonWriting.BuildStreamConfigurationsJson(streams);

            using JsonDocument document = JsonDocument.Parse(json);
            Assert.AreEqual(JsonValueKind.Array, document.RootElement.ValueKind);
            Assert.AreEqual(streams.Length, document.RootElement.GetArrayLength());

            int index = 0;
            foreach(JsonElement element in document.RootElement.EnumerateArray())
            {
                SsfStreamConfiguration? parsed = SsfStreamJsonParsing.ParseStreamConfiguration(element.GetRawText());
                Assert.IsNotNull(parsed);
                Assert.AreEqual(streams[index].StreamId, parsed.StreamId);
                ++index;
            }
        });
    }


    [TestMethod]
    public void TransmitterConfigurationWriteThenStrictParseRoundTrips()
    {
        Gen<Uri> issuerGen =
            from host in Gen.Char['a', 'z'].Array[1, 8].Select(static chars => new string(chars))
            select new Uri($"https://{host}.example/");

        Gen<IReadOnlyList<KeyValuePair<string, string>>> endpointMembersGen = Gen.OneOf(
            Gen.Const((IReadOnlyList<KeyValuePair<string, string>>)[]),
            JsonStringGen.Select(static url => (IReadOnlyList<KeyValuePair<string, string>>)
                [new KeyValuePair<string, string>(SsfMetadataParameterNames.JwksUri, url)]),
            Gen.Select(JsonStringGen, JsonStringGen, static (jwks, config) => (IReadOnlyList<KeyValuePair<string, string>>)
                [
                    new KeyValuePair<string, string>(SsfMetadataParameterNames.JwksUri, jwks),
                    new KeyValuePair<string, string>(SsfMetadataParameterNames.ConfigurationEndpoint, config)
                ]));

        //default_subjects is constrained to the values the strict parser accepts.
        Gen<string?> defaultSubjectsGen = Gen.OneOf(
            Gen.Const((string?)null),
            Gen.Const((string?)SsfMetadataParameterNames.DefaultSubjectsAll),
            Gen.Const((string?)SsfMetadataParameterNames.DefaultSubjectsNone));

        Gen<(Uri Issuer, IReadOnlyList<KeyValuePair<string, string>> Members, SsfTransmitterMetadataContribution Contribution)> caseGen =
            from issuer in issuerGen
            from members in endpointMembersGen
            from deliveryMethods in GenOption(StringListGen)
            from criticalMembers in GenOption(StringListGen)
            from specUrns in GenOption(StringListGen)
            from defaultSubjects in defaultSubjectsGen
            select (issuer, members, new SsfTransmitterMetadataContribution
            {
                DeliveryMethodsSupported = deliveryMethods,
                CriticalSubjectMembers = criticalMembers,
                AuthorizationSchemeSpecUrns = specUrns,
                DefaultSubjects = defaultSubjects
            });

        caseGen.Sample(testCase =>
        {
            string json = SsfTransmitterJsonWriting.BuildTransmitterConfigurationJson(
                testCase.Issuer, testCase.Members, testCase.Contribution);

            SsfTransmitterConfiguration? parsed = SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(json);

            Assert.IsNotNull(parsed, $"The emitted metadata must strict-parse. Json: {json}");
            Assert.AreEqual(testCase.Issuer.OriginalString, parsed.Issuer);
            Assert.AreEqual("1_0", parsed.SpecVersion);

            foreach(KeyValuePair<string, string> member in testCase.Members)
            {
                if(member.Key == SsfMetadataParameterNames.JwksUri)
                {
                    Assert.AreEqual(member.Value, parsed.JwksUri);
                }
                if(member.Key == SsfMetadataParameterNames.ConfigurationEndpoint)
                {
                    Assert.AreEqual(member.Value, parsed.ConfigurationEndpoint);
                }
            }

            AssertListsEqual(testCase.Contribution.DeliveryMethodsSupported, parsed.DeliveryMethodsSupported);
            AssertListsEqual(testCase.Contribution.CriticalSubjectMembers, parsed.CriticalSubjectMembers);
            AssertListsEqual(
                testCase.Contribution.AuthorizationSchemeSpecUrns,
                parsed.AuthorizationSchemes?.Select(static scheme => scheme.SpecUrn).ToArray());
            Assert.AreEqual(testCase.Contribution.DefaultSubjects, parsed.DefaultSubjects);
        });
    }


    [TestMethod]
    public void StreamStatusWriteThenStrictParseRoundTrips()
    {
        //The status value is constrained to the three the strict parser accepts
        //(SSF §8.1.2.1); stream_id and reason exercise the escaping paths.
        Gen<SsfStreamStatus> statusGen =
            from streamId in JsonStringGen
            from status in Gen.OneOf(
                Gen.Const(SsfStreamStatusValues.Enabled),
                Gen.Const(SsfStreamStatusValues.Paused),
                Gen.Const(SsfStreamStatusValues.Disabled))
            from reason in GenOption(JsonStringGen)
            select new SsfStreamStatus { StreamId = streamId, Status = status, Reason = reason };

        statusGen.Sample(status =>
        {
            string json = SsfTransmitterJsonWriting.BuildStreamStatusJson(status);
            SsfStreamStatus? parsed = SsfStreamJsonParsing.ParseStreamStatus(json);

            Assert.IsNotNull(parsed, $"The emitted status must strict-parse. Json: {json}");
            Assert.AreEqual(status.StreamId, parsed.StreamId);
            Assert.AreEqual(status.Status, parsed.Status);
            Assert.AreEqual(status.Reason, parsed.Reason);
        });
    }


    private static Gen<T?> GenOption<T>(Gen<T> gen) where T : class =>
        Gen.OneOf(Gen.Const(default(T)), gen.Select(static value => (T?)value));


    //The writers omit absent (null) members and the parsers return null for
    //omitted ones, so null-versus-null and sequence equality are the contract.
    private static void AssertListsEqual(IReadOnlyList<string>? expected, IReadOnlyList<string>? actual)
    {
        if(expected is null)
        {
            Assert.IsNull(actual);

            return;
        }

        Assert.IsNotNull(actual);
        Assert.IsTrue(expected.SequenceEqual(actual, StringComparer.Ordinal));
    }
}
