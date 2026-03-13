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
    private string TwoBitJson = StatusListTestConstants.TwoBitJson;

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
        using var original = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, SensitiveMemoryPool<byte>.Shared);
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
        using var list = StatusListType.Create(8, StatusListBitSize.OneBit, SensitiveMemoryPool<byte>.Shared);
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

    [TestMethod]
    public void StatusClaimRoundTrips()
    {
        var options = CreateOptions();
        var claim = StatusClaim.FromStatusList(SuspendedCredentialIndex, ExampleTokenSubject);

        string json = JsonSerializerExtensions.Serialize(claim, options);
        var deserialized = JsonSerializerExtensions.Deserialize<StatusClaim>(json, options)!;

        Assert.IsTrue(deserialized.HasStatusList);
        Assert.AreEqual(SuspendedCredentialIndex, deserialized.StatusList!.Value.Index);
    }

    [TestMethod]
    public void StatusClaimMatchesSpecFormat()
    {
        var options = CreateOptions();
        var claim = StatusClaim.FromStatusList(0, ExampleTokenSubject);

        string json = JsonSerializerExtensions.Serialize(claim, options);
        string expected = "{\"status_list\":{\"idx\":0,\"uri\":\"" + ExampleTokenSubject + "\"}}";

        Assert.AreEqual(expected, json);
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
}