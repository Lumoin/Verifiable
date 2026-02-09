using System.Text.Json;
using Verifiable.Json.Converters;

namespace Verifiable.Tests.Serialization;

[TestClass]
internal sealed class JsonDictionaryStringObjectJsonConverterTests
{
    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions();
        options.Converters.Add(new DictionaryStringObjectJsonConverter());
        return options;
    }

    [TestMethod]
    public void DeserializeEmptyObjectSucceeds()
    {
        const string json = /*lang=json,strict*/ "{}";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        Assert.IsEmpty(result);
    }

    [TestMethod]
    public void DeserializeStringValueSucceeds()
    {
        const string json = /*lang=json,strict*/ """{"name":"Alice"}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        Assert.AreEqual("Alice", result["name"]);
    }

    [TestMethod]
    public void DeserializeBooleanValuesSucceeds()
    {
        const string json = /*lang=json,strict*/ """{"active":true,"deleted":false}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        Assert.IsTrue((bool)result["active"]);
        Assert.IsFalse((bool)result["deleted"]);
    }

    [TestMethod]
    public void DeserializeNullValueSucceeds()
    {
        const string json = /*lang=json,strict*/ """{"value":null}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        Assert.IsNull(result["value"]);
    }

    [TestMethod]
    public void DeserializeIntegerValueSucceeds()
    {
        const string json = /*lang=json,strict*/ """{"count":42}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        Assert.AreEqual(42m, result["count"]);
    }

    [TestMethod]
    public void DeserializeDecimalValueSucceeds()
    {
        const string json = /*lang=json,strict*/ """{"price":19.99}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        Assert.AreEqual(19.99m, result["price"]);
    }

    [TestMethod]
    public void DeserializeLargeIntegerAsLongSucceeds()
    {
        const string json = /*lang=json,strict*/ """{"bigNumber":9223372036854775807}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        Assert.AreEqual(9223372036854775807m, result["bigNumber"]);
    }

    [TestMethod]
    public void DeserializeDateTimeStringAsDateTimeSucceeds()
    {
        const string json = /*lang=json,strict*/ """{"timestamp":"2024-01-15T10:30:00Z"}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        Assert.IsInstanceOfType<DateTime>(result["timestamp"]);
        var dateTime = (DateTime)result["timestamp"];
        Assert.AreEqual(2024, dateTime.Year);
        Assert.AreEqual(1, dateTime.Month);
        Assert.AreEqual(15, dateTime.Day);
    }

    [TestMethod]
    public void DeserializeNonDateTimeStringAsStringSucceeds()
    {
        const string json = /*lang=json,strict*/ """{"text":"not-a-date"}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        Assert.AreEqual("not-a-date", result["text"]);
    }

    [TestMethod]
    public void DeserializeNestedObjectSucceeds()
    {
        const string json = /*lang=json,strict*/ """{"outer":{"inner":"value"}}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        var outer = result["outer"] as Dictionary<string, object>;
        Assert.IsNotNull(outer);
        Assert.AreEqual("value", outer["inner"]);
    }

    [TestMethod]
    public void DeserializeArraySucceeds()
    {
        const string json = /*lang=json,strict*/ """{"items":["a","b","c"]}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        var items = result["items"] as List<object>;
        Assert.IsNotNull(items);
        Assert.HasCount(3, items);
        Assert.AreEqual("a", items[0]);
        Assert.AreEqual("b", items[1]);
        Assert.AreEqual("c", items[2]);
    }

    [TestMethod]
    public void DeserializeMixedArraySucceeds()
    {
        const string json = /*lang=json,strict*/ """{"mixed":[1,"two",true,null]}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        var mixed = result["mixed"] as List<object>;
        Assert.IsNotNull(mixed);
        Assert.HasCount(4, mixed);
        Assert.AreEqual(1m, mixed[0]);
        Assert.AreEqual("two", mixed[1]);
        Assert.IsTrue((bool)mixed[2]);
        Assert.IsNull(mixed[3]);
    }

    [TestMethod]
    public void DeserializeArrayOfObjectsSucceeds()
    {
        const string json = /*lang=json,strict*/ """{"people":[{"name":"Alice"},{"name":"Bob"}]}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        var people = result["people"] as List<object>;
        Assert.IsNotNull(people);
        Assert.HasCount(2, people);

        var alice = people[0] as Dictionary<string, object>;
        Assert.IsNotNull(alice);
        Assert.AreEqual("Alice", alice["name"]);

        var bob = people[1] as Dictionary<string, object>;
        Assert.IsNotNull(bob);
        Assert.AreEqual("Bob", bob["name"]);
    }

    [TestMethod]
    public void SerializeEmptyDictionarySucceeds()
    {
        var dictionary = new Dictionary<string, object>();
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual("{}", json);
    }

    [TestMethod]
    public void SerializeStringValueSucceeds()
    {
        var dictionary = new Dictionary<string, object> { ["name"] = "Alice" };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"name":"Alice"}""", json);
    }

    [TestMethod]
    public void SerializeBooleanValuesSucceeds()
    {
        var dictionary = new Dictionary<string, object>
        {
            ["active"] = true,
            ["deleted"] = false
        };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.Contains("\"active\":true", json, StringComparison.Ordinal);
        Assert.Contains("\"deleted\":false", json, StringComparison.Ordinal);
    }

    [TestMethod]
    public void SerializeNullValueSucceeds()
    {
        var dictionary = new Dictionary<string, object> { ["value"] = null! };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"value":null}""", json);
    }

    [TestMethod]
    public void SerializeIntegerValueSucceeds()
    {
        var dictionary = new Dictionary<string, object> { ["count"] = 42 };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"count":42}""", json);
    }

    [TestMethod]
    public void SerializeLongValueSucceeds()
    {
        var dictionary = new Dictionary<string, object> { ["bigNumber"] = 9223372036854775807L };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"bigNumber":9223372036854775807}""", json);
    }

    [TestMethod]
    public void SerializeFloatValueSucceeds()
    {
        var dictionary = new Dictionary<string, object> { ["value"] = 3.14f };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.Contains("3.14", json, StringComparison.Ordinal);
    }

    [TestMethod]
    public void SerializeDoubleValueSucceeds()
    {
        var dictionary = new Dictionary<string, object> { ["value"] = 3.14159265359 };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.Contains("3.14159265359", json, StringComparison.Ordinal);
    }

    [TestMethod]
    public void SerializeDecimalValueSucceeds()
    {
        var dictionary = new Dictionary<string, object> { ["price"] = 19.99m };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"price":19.99}""", json);
    }

    [TestMethod]
    public void SerializeDateTimeValueSucceeds()
    {
        var dateTime = new DateTime(2024, 1, 15, 10, 30, 0, DateTimeKind.Utc);
        var dictionary = new Dictionary<string, object> { ["timestamp"] = dateTime };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.Contains("2024-01-15", json, StringComparison.Ordinal);
    }

    [TestMethod]
    public void SerializeNestedDictionarySucceeds()
    {
        var dictionary = new Dictionary<string, object>
        {
            ["outer"] = new Dictionary<string, object> { ["inner"] = "value" }
        };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"outer":{"inner":"value"}}""", json);
    }

    [TestMethod]
    public void SerializeListSucceeds()
    {
        var dictionary = new Dictionary<string, object>
        {
            ["items"] = new List<object> { "a", "b", "c" }
        };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"items":["a","b","c"]}""", json);
    }

    [TestMethod]
    public void SerializeMixedListSucceeds()
    {
        var dictionary = new Dictionary<string, object>
        {
            ["mixed"] = new List<object> { 1, "two", true, null! }
        };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"mixed":[1,"two",true,null]}""", json);
    }

    [TestMethod]
    public void RoundtripComplexObjectSucceeds()
    {
        const string originalJson = /*lang=json,strict*/ """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": "http://example.org/credentials/123",
                "type": ["VerifiableCredential"],
                "issuer": {
                    "id": "did:example:123",
                    "name": "Example Issuer"
                },
                "validFrom": "2024-01-01T00:00:00Z",
                "credentialSubject": {
                    "id": "did:example:456",
                    "degree": {
                        "type": "BachelorDegree",
                        "name": "Bachelor of Science"
                    }
                }
            }
            """;
        var options = CreateOptions();

        var dictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(originalJson, options);
        Assert.IsNotNull(dictionary);

        string serializedJson = JsonSerializer.Serialize(dictionary, options);
        var roundtrippedDictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(serializedJson, options);

        Assert.IsNotNull(roundtrippedDictionary);
        Assert.AreEqual("http://example.org/credentials/123", roundtrippedDictionary["id"]);

        var issuer = roundtrippedDictionary["issuer"] as Dictionary<string, object>;
        Assert.IsNotNull(issuer);
        Assert.AreEqual("did:example:123", issuer["id"]);
        Assert.AreEqual("Example Issuer", issuer["name"]);
    }

    [TestMethod]
    public void SerializeJsonElementObjectSucceeds()
    {
        //Simulates the scenario where a dictionary contains JsonElement values
        //from another deserialization context.
        const string sourceJson = /*lang=json,strict*/ """{"nested":{"key":"value"}}""";
        using var document = JsonDocument.Parse(sourceJson);
        var nestedElement = document.RootElement.GetProperty("nested");

        var dictionary = new Dictionary<string, object> { ["data"] = nestedElement };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"data":{"key":"value"}}""", json);
    }

    [TestMethod]
    public void SerializeJsonElementArraySucceeds()
    {
        const string sourceJson = /*lang=json,strict*/ """{"items":[1,2,3]}""";
        using var document = JsonDocument.Parse(sourceJson);
        var arrayElement = document.RootElement.GetProperty("items");

        var dictionary = new Dictionary<string, object> { ["numbers"] = arrayElement };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"numbers":[1,2,3]}""", json);
    }

    [TestMethod]
    public void SerializeJsonElementStringSucceeds()
    {
        const string sourceJson = /*lang=json,strict*/ """{"text":"hello"}""";
        using var document = JsonDocument.Parse(sourceJson);
        var stringElement = document.RootElement.GetProperty("text");

        var dictionary = new Dictionary<string, object> { ["message"] = stringElement };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"message":"hello"}""", json);
    }

    [TestMethod]
    public void SerializeJsonElementNumberSucceeds()
    {
        const string sourceJson = /*lang=json,strict*/ """{"value":42.5}""";
        using var document = JsonDocument.Parse(sourceJson);
        var numberElement = document.RootElement.GetProperty("value");

        var dictionary = new Dictionary<string, object> { ["amount"] = numberElement };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"amount":42.5}""", json);
    }

    [TestMethod]
    public void SerializeJsonElementBooleanSucceeds()
    {
        const string sourceJson = /*lang=json,strict*/ """{"flag":true}""";
        using var document = JsonDocument.Parse(sourceJson);
        var boolElement = document.RootElement.GetProperty("flag");

        var dictionary = new Dictionary<string, object> { ["enabled"] = boolElement };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"enabled":true}""", json);
    }

    [TestMethod]
    public void SerializeJsonElementNullSucceeds()
    {
        const string sourceJson = /*lang=json,strict*/ """{"nothing":null}""";
        using var document = JsonDocument.Parse(sourceJson);
        var nullElement = document.RootElement.GetProperty("nothing");

        var dictionary = new Dictionary<string, object> { ["empty"] = nullElement };
        var options = CreateOptions();

        string json = JsonSerializer.Serialize(dictionary, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"empty":null}""", json);
    }

    [TestMethod]
    public void DeserializeNonObjectThrowsJsonException()
    {
        const string json = /*lang=json,strict*/ """[1,2,3]""";
        var options = CreateOptions();

        _ = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<Dictionary<string, object>>(json, options));
    }

    [TestMethod]
    public void SerializeNullDictionaryThrowsArgumentNullException()
    {
        var options = CreateOptions();
        var converter = new DictionaryStringObjectJsonConverter();

        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream);

        _ = Assert.Throws<ArgumentNullException>(() =>
            converter.Write(writer, null!, options));
    }

    [TestMethod]
    public void SerializeUnsupportedTypeThrowsNotSupportedException()
    {
        var dictionary = new Dictionary<string, object> { ["guid"] = Guid.NewGuid() };
        var options = CreateOptions();

        _ = Assert.Throws<NotSupportedException>(() =>
            JsonSerializer.Serialize(dictionary, options));
    }

    [TestMethod]
    public void DeserializeDeeplyNestedObjectSucceeds()
    {
        const string json = /*lang=json,strict*/ """
            {
                "level1": {
                    "level2": {
                        "level3": {
                            "level4": {
                                "value": "deep"
                            }
                        }
                    }
                }
            }
            """;
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        var level1 = result["level1"] as Dictionary<string, object>;
        Assert.IsNotNull(level1);
        var level2 = level1["level2"] as Dictionary<string, object>;
        Assert.IsNotNull(level2);
        var level3 = level2["level3"] as Dictionary<string, object>;
        Assert.IsNotNull(level3);
        var level4 = level3["level4"] as Dictionary<string, object>;
        Assert.IsNotNull(level4);
        Assert.AreEqual("deep", level4["value"]);
    }

    [TestMethod]
    public void RoundtripPreservesNumericPrecision()
    {
        const string json = /*lang=json,strict*/ """{"integer":42,"decimal":3.14159265358979}""";
        var options = CreateOptions();

        var dictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);
        Assert.IsNotNull(dictionary);

        string serialized = JsonSerializer.Serialize(dictionary, options);
        var roundtripped = JsonSerializer.Deserialize<Dictionary<string, object>>(serialized, options);

        Assert.IsNotNull(roundtripped);
        Assert.AreEqual(42m, roundtripped["integer"]);
        Assert.AreEqual(3.14159265358979m, roundtripped["decimal"]);
    }

    [TestMethod]
    public void DeserializeEmptyArraySucceeds()
    {
        const string json = /*lang=json,strict*/ """{"items":[]}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        var items = result["items"] as List<object>;
        Assert.IsNotNull(items);
        Assert.IsEmpty(items);
    }

    [TestMethod]
    public void DeserializeNestedArraysSucceeds()
    {
        const string json = /*lang=json,strict*/ """{"matrix":[[1,2],[3,4]]}""";
        var options = CreateOptions();

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

        Assert.IsNotNull(result);
        var matrix = result["matrix"] as List<object>;
        Assert.IsNotNull(matrix);
        Assert.HasCount(2, matrix);

        var row1 = matrix[0] as List<object>;
        Assert.IsNotNull(row1);
        Assert.AreEqual(1m, row1[0]);
        Assert.AreEqual(2m, row1[1]);

        var row2 = matrix[1] as List<object>;
        Assert.IsNotNull(row2);
        Assert.AreEqual(3m, row2[0]);
        Assert.AreEqual(4m, row2[1]);
    }
}