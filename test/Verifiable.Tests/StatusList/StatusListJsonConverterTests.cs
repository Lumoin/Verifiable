using System.Buffers;
using System.Text.Json;
using Verifiable.Core.StatusList;
using Verifiable.Json.StatusList;

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
    /// Gets a shared memory pool for managing buffers of bytes.
    /// </summary>
    /// <remarks>The returned memory pool is a singleton instance that can be used to efficiently rent and
    /// return byte buffers. Using a shared pool helps reduce memory allocations and improve performance in scenarios
    /// that require frequent buffer management.</remarks>
    private static MemoryPool<byte> Pool => MemoryPool<byte>.Shared;

    /// <summary>
    /// Gets or sets the context information for the current test run.
    /// </summary>
    /// <remarks>The test context provides access to information such as test name, test results directory,
    /// and other runtime data relevant to the execution of the test. This property is typically set by the test
    /// framework and should not be modified by user code.</remarks>
    public TestContext TestContext { get; set; } = null!;

    
    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions();
        options.Converters.Add(new StatusListJsonConverter(Pool));
        options.Converters.Add(new StatusListReferenceJsonConverter());
        options.Converters.Add(new StatusClaimJsonConverter());
        options.Converters.Add(new StatusListAggregationJsonConverter());

        return options;
    }

    [TestMethod]
    public void OneBitSpecVectorDeserializesCorrectly()
    {
        var options = CreateOptions();

        using var deserialized = JsonSerializer.Deserialize<StatusListType>(OneBitJson, options)!;
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
        using var original = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        original[0] = StatusTypes.Invalid;
        original[3] = StatusTypes.Invalid;
        original[7] = StatusTypes.Invalid;

        string json = JsonSerializer.Serialize(original, options);
        using var restored = JsonSerializer.Deserialize<StatusListType>(json, options)!;

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

        using var deserialized = JsonSerializer.Deserialize<StatusListType>(TwoBitJson, options)!;
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
        using var list = StatusListType.Create(8, StatusListBitSize.OneBit, Pool);
        list.AggregationUri = ExampleAggregationUri;

        string json = JsonSerializer.Serialize(list, options);
        Assert.Contains("aggregation_uri", json, StringComparison.Ordinal);

        using var deserialized = JsonSerializer.Deserialize<StatusListType>(json, options)!;
        Assert.AreEqual(ExampleAggregationUri, deserialized.AggregationUri);
    }

    [TestMethod]
    public void StatusListReferenceRoundTrips()
    {
        var options = CreateOptions();
        var reference = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);

        string json = JsonSerializer.Serialize(reference, options);
        var deserialized = JsonSerializer.Deserialize<StatusListReference>(json, options);

        Assert.AreEqual(reference, deserialized);
    }

    [TestMethod]
    public void StatusListReferenceMatchesSpecFormat()
    {
        var options = CreateOptions();
        var reference = new StatusListReference(0, ExampleTokenSubject);

        string json = JsonSerializer.Serialize(reference, options);
        string expected = "{\"idx\":0,\"uri\":\"" + ExampleTokenSubject + "\"}";

        Assert.AreEqual(expected, json);
    }

    [TestMethod]
    public void StatusClaimRoundTrips()
    {
        var options = CreateOptions();
        var claim = StatusClaim.FromStatusList(SuspendedCredentialIndex, ExampleTokenSubject);

        string json = JsonSerializer.Serialize(claim, options);
        var deserialized = JsonSerializer.Deserialize<StatusClaim>(json, options)!;

        Assert.IsTrue(deserialized.HasStatusList);
        Assert.AreEqual(SuspendedCredentialIndex, deserialized.StatusList!.Value.Index);
    }

    [TestMethod]
    public void StatusClaimMatchesSpecFormat()
    {
        var options = CreateOptions();
        var claim = StatusClaim.FromStatusList(0, ExampleTokenSubject);

        string json = JsonSerializer.Serialize(claim, options);
        string expected = "{\"status_list\":{\"idx\":0,\"uri\":\"" + ExampleTokenSubject + "\"}}";

        Assert.AreEqual(expected, json);
    }

    [TestMethod]
    public void StatusListAggregationRoundTrips()
    {
        var options = CreateOptions();
        var aggregation = new StatusListAggregation([ExampleTokenSubject, SecondTokenSubject]);

        string json = JsonSerializer.Serialize(aggregation, options);
        var deserialized = JsonSerializer.Deserialize<StatusListAggregation>(json, options)!;

        Assert.HasCount(2, deserialized.StatusLists);
    }

    [TestMethod]
    public void StatusListMissingBitsThrowsJsonException()
    {
        var options = CreateOptions();
        const string json = /*lang=json,strict*/ """{"lst":"eNrbuRgAAhcBXQ"}""";

        Assert.ThrowsExactly<JsonException>(() =>
            JsonSerializer.Deserialize<StatusListType>(json, options));
    }

    [TestMethod]
    public void StatusListMissingLstThrowsJsonException()
    {
        var options = CreateOptions();
        const string json = /*lang=json,strict*/ """{"bits":1}""";

        Assert.ThrowsExactly<JsonException>(() =>
            JsonSerializer.Deserialize<StatusListType>(json, options));
    }

    [TestMethod]
    public void ReferenceMissingIdxThrowsJsonException()
    {
        var options = CreateOptions();
        string json = "{\"uri\":\"" + ExampleTokenSubject + "\"}";

        Assert.ThrowsExactly<JsonException>(() =>
            JsonSerializer.Deserialize<StatusListReference>(json, options));
    }

    [TestMethod]
    public void ReferenceMissingUriThrowsJsonException()
    {
        var options = CreateOptions();
        const string json = /*lang=json,strict*/ """{"idx":0}""";

        Assert.ThrowsExactly<JsonException>(() =>
            JsonSerializer.Deserialize<StatusListReference>(json, options));
    }   
}