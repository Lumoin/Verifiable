using System.Text.Json;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for the Status List JSON converters.
/// </summary>
[TestClass]
internal sealed class StatusListJsonConverterTests
{
    /// <summary>
    /// Gets the default capacity for small status lists used in tests.
    /// </summary>
    private int SmallListCapacity { get; } = StatusListTestConstants.SmallListCapacity;

    /// <summary>
    /// Gets the index of the suspended credential used for testing purposes.
    /// </summary>
    private int SuspendedCredentialIndex { get; } = StatusListTestConstants.SuspendedCredentialIndex;

    /// <summary>
    /// Gets the example subject value used for token generation in test scenarios.
    /// </summary>
    private string ExampleTokenSubject { get; } = StatusListTestConstants.ExampleTokenSubject;

    /// <summary>
    /// Gets the subject identifier associated with the second token.
    /// </summary>
    private string SecondTokenSubject { get; } = StatusListTestConstants.SecondTokenSubject;

    /// <summary>
    /// Gets the example aggregation URI used for test scenarios.
    /// </summary>
    private string ExampleAggregationUri { get; } = StatusListTestConstants.ExampleAggregationUri;

    /// <summary>
    /// Gets the JSON-encoded string representing a one-bit status list for testing purposes.
    /// </summary>
    private string OneBitJson { get; } = StatusListTestConstants.OneBitJson;

    /// <summary>
    /// Contains the JSON string used for two-bit status list testing.
    /// </summary>
    private string TwoBitJson { get; } = StatusListTestConstants.TwoBitJson;

    /// <summary>
    /// Gets or sets the context information for the current test run.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    private static JsonSerializerOptions CreateOptions() =>
        new JsonSerializerOptions().ApplyVerifiableDefaults();


    [TestMethod]
    public void OneBitSpecVectorDeserializesCorrectly()
    {
        var options = CreateOptions();

        using var deserialized = JsonSerializerExtensions.Deserialize<StatusListType>(OneBitJson, options)!;
        Assert.AreEqual(StatusListBitSize.OneBit, deserialized.BitSize);
        Assert.AreEqual(StatusTypes.Invalid, deserialized[0]);
        Assert.AreEqual(StatusTypes.Valid, deserialized[1]);
        Assert.AreEqual(StatusTypes.Valid, deserialized[2]);
        Assert.AreEqual(StatusTypes.Invalid, deserialized[3]);
    }

    [TestMethod]
    public void OneBitRoundTripsViaJson()
    {
        var options = CreateOptions();
        using var original = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.LeastSignificantFirst);
        original[0] = StatusTypes.Invalid;
        original[3] = StatusTypes.Invalid;
        original[7] = StatusTypes.Invalid;

        string json = JsonSerializerExtensions.Serialize(original, options);
        using var restored = JsonSerializerExtensions.Deserialize<StatusListType>(json, options)!;

        Assert.AreEqual(StatusListBitSize.OneBit, restored.BitSize);
        Assert.AreEqual(StatusTypes.Invalid, restored[0]);
        Assert.AreEqual(StatusTypes.Valid, restored[1]);
        Assert.AreEqual(StatusTypes.Invalid, restored[3]);
        Assert.AreEqual(StatusTypes.Invalid, restored[7]);
    }

    [TestMethod]
    public void TwoBitSpecVectorDeserializesCorrectly()
    {
        var options = CreateOptions();

        using var deserialized = JsonSerializerExtensions.Deserialize<StatusListType>(TwoBitJson, options)!;
        Assert.AreEqual(StatusListBitSize.TwoBits, deserialized.BitSize);
        Assert.AreEqual(StatusTypes.Invalid, deserialized[0]);
        Assert.AreEqual(StatusTypes.Suspended, deserialized[1]);
        Assert.AreEqual(StatusTypes.Valid, deserialized[2]);
        Assert.AreEqual(StatusTypes.ApplicationSpecific03, deserialized[3]);
    }

    [TestMethod]
    public void StatusListWithAggregationUriRoundTrips()
    {
        var options = CreateOptions();
        using var list = StatusListType.Create(8, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.LeastSignificantFirst);
        list.AggregationUri = ExampleAggregationUri;

        string json = JsonSerializerExtensions.Serialize(list, options);
        Assert.Contains("aggregation_uri", json, StringComparison.Ordinal);

        using var deserialized = JsonSerializerExtensions.Deserialize<StatusListType>(json, options)!;
        Assert.AreEqual(ExampleAggregationUri, deserialized.AggregationUri);
    }

    [TestMethod]
    public void StatusListReferenceRoundTrips()
    {
        var options = CreateOptions();
        var reference = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);

        string json = JsonSerializerExtensions.Serialize(reference, options);
        var deserialized = JsonSerializerExtensions.Deserialize<StatusListReference>(json, options);

        Assert.AreEqual(reference, deserialized);
    }

    [TestMethod]
    public void StatusListReferenceMatchesSpecFormat()
    {
        var options = CreateOptions();
        var reference = new StatusListReference(0, ExampleTokenSubject);

        string json = JsonSerializerExtensions.Serialize(reference, options);
        string expected = "{\"idx\":0,\"uri\":\"" + ExampleTokenSubject + "\"}";

        Assert.AreEqual(expected, json);
    }

    /// <summary>
    /// "status_list: REQUIRED when the status mechanism defined in this specification is used. It MUST
    /// specify a JSON Object that contains a reference to a Status List Token."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// A claim naming only that mechanism survives a write and a read unchanged — the mechanism set
    /// included, since the set is what tells a verifier which mechanisms the issuer stated.
    /// </summary>
    [TestMethod]
    public void StatusClaimRoundTrips()
    {
        var options = CreateOptions();
        var claim = StatusClaim.FromStatusList(SuspendedCredentialIndex, ExampleTokenSubject);

        string json = JsonSerializerExtensions.Serialize(claim, options);
        var deserialized = JsonSerializerExtensions.Deserialize<StatusClaim>(json, options)!;

        Assert.IsTrue(deserialized.HasStatusList, "The written claim named status_list, so the read claim must carry its reference.");
        Assert.AreEqual(SuspendedCredentialIndex, deserialized.StatusList!.Value.Index, "idx must survive the round trip exactly.");
        Assert.AreEqual(ExampleTokenSubject, deserialized.StatusList!.Value.Uri, "uri must survive the round trip exactly.");
        Assert.AreEqual(claim, deserialized, "A claim read back from its own serialization is the same claim.");
    }

    /// <summary>
    /// "status_list: REQUIRED when the status mechanism defined in this specification is used. It MUST
    /// specify a JSON Object that contains a reference to a Status List Token. It MUST at least
    /// contain the following claims: idx: REQUIRED. … uri: REQUIRED."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// The wire shape is asserted as text, not through the reader, so the two directions cannot agree
    /// on a spelling the specification does not define.
    /// </summary>
    [TestMethod]
    public void StatusClaimMatchesSpecFormat()
    {
        var options = CreateOptions();
        var claim = StatusClaim.FromStatusList(0, ExampleTokenSubject);

        string json = JsonSerializerExtensions.Serialize(claim, options);
        string expected = "{\"status_list\":{\"idx\":0,\"uri\":\"" + ExampleTokenSubject + "\"}}";

        Assert.AreEqual(expected, json, "A claim naming status_list alone is written as exactly the Section 6.2 object.");
    }

    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// "at least one" licenses more than one, so every member name is a mechanism the issuer stated:
    /// reading records them all and still decodes the reference the modelled mechanism carries.
    /// </summary>
    [TestMethod]
    public void ReadingAClaimNamingTwoMechanismsRecordsBothAndDecodesTheReference()
    {
        var options = CreateOptions();
        const string Json = /*lang=json,strict*/ """
            {"status_list":{"idx":42,"uri":"https://example.com/statuslists/1"},"identifier_list":{"id":"6fc2-a3b1","uri":"https://example.com/identifierlists/1"}}
            """;

        var claim = JsonSerializerExtensions.Deserialize<StatusClaim>(Json, options)!;

        Assert.HasCount(2, claim.Mechanisms, "Both member names are status mechanisms the issuer named.");
        Assert.Contains(StatusMechanismNames.StatusList, claim.Mechanisms, "status_list is one of the two mechanisms named.");
        Assert.Contains(StatusMechanismNames.IdentifierList, claim.Mechanisms, "The mechanism this library does not model must still reach the caller by name.");
        Assert.AreEqual(SuspendedCredentialIndex, claim.StatusList!.Value.Index, "The status_list member decodes even beside an unmodelled mechanism.");
        Assert.AreEqual(ExampleTokenSubject, claim.StatusList!.Value.Uri, "The status_list member decodes even beside an unmodelled mechanism.");
    }

    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// A claim naming only a mechanism this library does not evaluate is a valid claim carrying no
    /// reference, not a malformed one: the issuer did gate the token's validity on something, and a
    /// reader that refused it would report the same answer as a token with no status claim at all.
    /// </summary>
    [TestMethod]
    public void ReadingAClaimNamingOnlyAnUnmodelledMechanismYieldsNoReference()
    {
        var options = CreateOptions();
        const string Json = /*lang=json,strict*/ """{"identifier_list":{"id":"6fc2-a3b1","uri":"https://example.com/identifierlists/1"}}""";

        var claim = JsonSerializerExtensions.Deserialize<StatusClaim>(Json, options)!;

        Assert.IsNull(claim.StatusList, "No status_list member is present, so there is no reference to decode.");
        Assert.HasCount(1, claim.Mechanisms, "Exactly the one mechanism the object named is recorded.");
        Assert.Contains(StatusMechanismNames.IdentifierList, claim.Mechanisms, "The mechanism the issuer named must reach the caller by name.");
    }

    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// An object present but empty names no mechanism, so it is refused rather than read as a claim
    /// naming nothing.
    /// </summary>
    [TestMethod]
    public void ReadingAClaimWithNoMemberThrowsJsonException()
    {
        var options = CreateOptions();
        const string Json = /*lang=json,strict*/ """{}""";

        JsonException exception = Assert.ThrowsExactly<JsonException>(() =>
            JsonSerializerExtensions.Deserialize<StatusClaim>(Json, options));

        Assert.Contains("at least one", exception.Message, "The refusal must name Section 6.1's at-least-one-mechanism requirement.");
    }

    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// One member names one mechanism, so an object repeating <c>status_list</c> states two references
    /// for one mechanism: a reader taking the first member and a reader taking the last would resolve
    /// different Status List Tokens for the same credential. The claim is refused rather than one of
    /// the two silently winning.
    /// </summary>
    [TestMethod]
    public void ReadingAClaimRepeatingTheStatusListMemberThrowsJsonException()
    {
        var options = CreateOptions();
        const string Json = """
            {"status_list":{"idx":42,"uri":"https://example.com/statuslists/1"},"status_list":{"idx":43,"uri":"https://example.com/statuslists/2"}}
            """;

        JsonException exception = Assert.ThrowsExactly<JsonException>(() =>
            JsonSerializerExtensions.Deserialize<StatusClaim>(Json, options));

        Assert.Contains(StatusMechanismNames.StatusList, exception.Message, "The refusal must name the repeated mechanism member.");
    }

    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// The rule is the member's, not the modelled mechanism's: a mechanism this library does not
    /// evaluate is repeated with the same ambiguity, and recording it once would hide from the relying
    /// party that the issuer stated it twice with different contents.
    /// </summary>
    [TestMethod]
    public void ReadingAClaimRepeatingAnUnmodelledMemberThrowsJsonException()
    {
        var options = CreateOptions();
        const string Json = """
            {"identifier_list":{"id":"6fc2-a3b1","uri":"https://example.com/identifierlists/1"},"identifier_list":{"id":"6fc2-a3b2","uri":"https://example.com/identifierlists/2"}}
            """;

        JsonException exception = Assert.ThrowsExactly<JsonException>(() =>
            JsonSerializerExtensions.Deserialize<StatusClaim>(Json, options));

        Assert.Contains(StatusMechanismNames.IdentifierList, exception.Message, "The refusal must name the repeated mechanism member.");
    }

    /// <summary>
    /// "the key MUST be a CBOR text string (major type 3) specifying the identifier of the status
    /// mechanism and the corresponding value defines its contents. status_list (status list):
    /// REQUIRED when the status mechanism defined in this specification is used."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">Token Status List, Section 6.3</see>.
    /// The status list mechanism is the only one whose value shape either encoding of this
    /// specification defines, so a claim naming another mechanism cannot be written and the attempt is
    /// refused rather than silently dropping the issuer's statement — the same posture the CBOR writer
    /// of the same structure takes, proved by
    /// <see cref="Verifiable.Tests.Mdoc.MdocCborMsoStatusTests.WriteMsoRefusesStatusMechanismOtherThanStatusList"/>.
    /// </summary>
    [TestMethod]
    public void WritingAClaimNamingAnUnmodelledMechanismIsRefused()
    {
        var options = CreateOptions();
        var claim = new StatusClaim(
            statusList: null,
            mechanisms: new HashSet<string>(StringComparer.Ordinal) { StatusMechanismNames.IdentifierList });

        NotSupportedException exception = Assert.ThrowsExactly<NotSupportedException>(() =>
            JsonSerializerExtensions.Serialize(claim, options));

        Assert.Contains(StatusMechanismNames.IdentifierList, exception.Message, "The refusal must name the mechanism that cannot be encoded.");
    }

    [TestMethod]
    public void StatusListAggregationRoundTrips()
    {
        var options = CreateOptions();
        var aggregation = new StatusListAggregation([ExampleTokenSubject, SecondTokenSubject]);

        string json = JsonSerializerExtensions.Serialize(aggregation, options);
        var deserialized = JsonSerializerExtensions.Deserialize<StatusListAggregation>(json, options)!;

        Assert.HasCount(2, deserialized.StatusLists);
    }

    [TestMethod]
    public void StatusListMissingBitsThrowsJsonException()
    {
        var options = CreateOptions();
        const string json = /*lang=json,strict*/ """{"lst":"eNrbuRgAAhcBXQ"}""";

        Assert.ThrowsExactly<JsonException>(() =>
            JsonSerializerExtensions.Deserialize<StatusListType>(json, options));
    }

    [TestMethod]
    public void StatusListMissingLstThrowsJsonException()
    {
        var options = CreateOptions();
        const string json = /*lang=json,strict*/ """{"bits":1}""";

        Assert.ThrowsExactly<JsonException>(() =>
            JsonSerializerExtensions.Deserialize<StatusListType>(json, options));
    }

    [TestMethod]
    public void ReferenceMissingIdxThrowsJsonException()
    {
        var options = CreateOptions();
        string json = "{\"uri\":\"" + ExampleTokenSubject + "\"}";

        Assert.ThrowsExactly<JsonException>(() =>
            JsonSerializerExtensions.Deserialize<StatusListReference>(json, options));
    }

    [TestMethod]
    public void ReferenceMissingUriThrowsJsonException()
    {
        var options = CreateOptions();
        const string json = /*lang=json,strict*/ """{"idx":0}""";

        Assert.ThrowsExactly<JsonException>(() =>
            JsonSerializerExtensions.Deserialize<StatusListReference>(json, options));
    }

    /// <summary>
    /// "Each index identifies a contiguous block of bits in the byte array, with the blocks being
    /// packed into bytes from the least significant bit (&quot;0&quot;) to the most significant bit
    /// (&quot;7&quot;)." A <see cref="StatusListType"/> packed <see cref="BitOrder.MostSignificantFirst"/>
    /// (the W3C Bitstring Status List's order) is refused rather than written as a Section 4.2 JSON
    /// object with its bytes copied as-is.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.1">Token Status List, Section 4.1</see>.
    /// </summary>
    [TestMethod]
    public void WritingRefusesAListPackedMostSignificantFirst()
    {
        var options = CreateOptions();
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.MostSignificantFirst);
        list[0] = StatusTypes.Invalid;

        var thrown = Assert.ThrowsExactly<ArgumentException>(() =>
            JsonSerializerExtensions.Serialize(list, options));

        Assert.AreEqual("value", thrown.ParamName, "The refusal must name the parameter carrying the wrongly ordered list.");
        Assert.Contains("section-4.1", thrown.Message, StringComparison.OrdinalIgnoreCase, "The refusal must anchor to Section 4.1.");
    }
}