using System.Text.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.TestInfrastructureTests;

/// <summary>
/// Tests for <see cref="JsonTestingUtilities"/> to ensure the test infrastructure itself is correct.
/// </summary>
[TestClass]
internal sealed class JsonTestingUtilitiesTests
{
    private static JsonSerializerOptions DefaultOptions { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };


    [TestMethod]
    public void CompareJsonElementsReturnsTrueForIdenticalJson()
    {
        const string json = /*lang=json,strict*/ """{"name":"test","value":42}""";

        var result = JsonTestingUtilities.CompareJsonElements(json, json);

        Assert.IsTrue(result);
    }


    [TestMethod]
    public void CompareJsonElementsReturnsTrueForEquivalentJsonWithDifferentWhitespace()
    {
        const string compact = /*lang=json,strict*/ """{"name":"test","value":42}""";
        const string formatted = /*lang=json,strict*/ """
            {
                "name": "test",
                "value": 42
            }
            """;

        var result = JsonTestingUtilities.CompareJsonElements(compact, formatted);

        Assert.IsTrue(result);
    }


    [TestMethod]
    public void CompareJsonElementsReturnsTrueForEquivalentJsonWithDifferentPropertyOrder()
    {
        const string order1 = /*lang=json,strict*/ """{"name":"test","value":42}""";
        const string order2 = /*lang=json,strict*/ """{"value":42,"name":"test"}""";

        var result = JsonTestingUtilities.CompareJsonElements(order1, order2);

        Assert.IsTrue(result);
    }


    [TestMethod]
    public void CompareJsonElementsReturnsFalseForDifferentValues()
    {
        const string json1 = /*lang=json,strict*/ """{"name":"test","value":42}""";
        const string json2 = /*lang=json,strict*/ """{"name":"test","value":43}""";

        var result = JsonTestingUtilities.CompareJsonElements(json1, json2);

        Assert.IsFalse(result);
    }


    [TestMethod]
    public void CompareJsonElementsReturnsFalseForDifferentPropertyNames()
    {
        const string json1 = /*lang=json,strict*/ """{"name":"test"}""";
        const string json2 = /*lang=json,strict*/ """{"title":"test"}""";

        var result = JsonTestingUtilities.CompareJsonElements(json1, json2);

        Assert.IsFalse(result);
    }


    [TestMethod]
    public void CompareJsonElementsReturnsFalseForDifferentArrayLengths()
    {
        const string json1 = /*lang=json,strict*/ """{"items":[1,2,3]}""";
        const string json2 = /*lang=json,strict*/ """{"items":[1,2]}""";

        var result = JsonTestingUtilities.CompareJsonElements(json1, json2);

        Assert.IsFalse(result);
    }


    [TestMethod]
    public void CompareJsonElementsReturnsFalseForDifferentArrayOrder()
    {
        //Array order matters in JSON equality.
        const string json1 = /*lang=json,strict*/ """{"items":[1,2,3]}""";
        const string json2 = /*lang=json,strict*/ """{"items":[3,2,1]}""";

        var result = JsonTestingUtilities.CompareJsonElements(json1, json2);

        Assert.IsFalse(result);
    }


    [TestMethod]
    public void CompareJsonElementsReturnsTrueForNestedObjectsWithDifferentOrder()
    {
        const string json1 = /*lang=json,strict*/ """{"outer":{"a":1,"b":2},"name":"test"}""";
        const string json2 = /*lang=json,strict*/ """{"name":"test","outer":{"b":2,"a":1}}""";

        var result = JsonTestingUtilities.CompareJsonElements(json1, json2);

        Assert.IsTrue(result);
    }


    [TestMethod]
    public void CompareJsonElementsReturnsTrueForNullValues()
    {
        const string json1 = /*lang=json,strict*/ """{"value":null}""";
        const string json2 = /*lang=json,strict*/ """{"value":null}""";

        var result = JsonTestingUtilities.CompareJsonElements(json1, json2);

        Assert.IsTrue(result);
    }


    [TestMethod]
    public void CompareJsonElementsReturnsFalseForNullVsNonNull()
    {
        const string json1 = /*lang=json,strict*/ """{"value":null}""";
        const string json2 = /*lang=json,strict*/ """{"value":"text"}""";

        var result = JsonTestingUtilities.CompareJsonElements(json1, json2);

        Assert.IsFalse(result);
    }


    [TestMethod]
    public void PerformSerializationCycleDeserializesAndReserializes()
    {
        const string inputJson = /*lang=json,strict*/ """{"name":"test","value":42}""";

        var (deserializedObject, reserializedString) = JsonTestingUtilities.PerformSerializationCycle<TestDocument>(inputJson, DefaultOptions);

        Assert.IsNotNull(deserializedObject);
        Assert.AreEqual("test", deserializedObject.Name);
        Assert.AreEqual(42, deserializedObject.Value);
        Assert.IsNotNull(reserializedString);

        //Verify round-trip produces equivalent JSON.
        var isEquivalent = JsonTestingUtilities.CompareJsonElements(inputJson, reserializedString);
        Assert.IsTrue(isEquivalent);
    }


    [TestMethod]
    public void PerformExtendedSerializationCycleDeserializesToBothTypes()
    {
        const string inputJson = /*lang=json,strict*/ """{"name":"test","value":42,"extra":"data"}""";

        var (obj1, obj2, reserializedString1, reserializedString2) =
            JsonTestingUtilities.PerformExtendedSerializationCycle<TestDocument, TestDocumentExtended>(inputJson, DefaultOptions);

        Assert.IsNotNull(obj1);
        Assert.IsNotNull(obj2);
        Assert.AreEqual("test", obj1.Name);
        Assert.AreEqual("test", obj2.Name);
        Assert.AreEqual("data", obj2.Extra);
    }


    private sealed class TestDocument
    {
        public string? Name { get; set; }

        public int Value { get; set; }
    }


    private sealed class TestDocumentExtended
    {
        public string? Name { get; set; }

        public int Value { get; set; }

        public string? Extra { get; set; }
    }
}