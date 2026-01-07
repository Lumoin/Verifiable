using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Json;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Tests for <see cref="Jcs"/> JSON Canonicalization Scheme implementation.
/// Test vectors derived from <see href="https://datatracker.ietf.org/doc/html/rfc8785">RFC 8785</see> examples.
/// </summary>
[TestClass]
public sealed class JcsTests
{
    [TestMethod]
    public void CanonicalizeRemovesWhitespace()
    {
        const string input = /*lang=json,strict*/ """
            {
                "name": "value",
                "array": [
                    1,
                    2,
                    3
                ]
            }
            """;

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ """{"array":[1,2,3],"name":"value"}""", result);
    }


    [TestMethod]
    public void CanonicalizeSortsObjectProperties()
    {
        const string input = /*lang=json,strict*/ """{"z":"last","a":"first","m":"middle"}""";

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ """{"a":"first","m":"middle","z":"last"}""", result);
    }


    [TestMethod]
    public void CanonicalizeSortsNestedObjectProperties()
    {
        const string input = /*lang=json,strict*/ """{"outer":{"z":"last","a":"first"}}""";

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ """{"outer":{"a":"first","z":"last"}}""", result);
    }


    [TestMethod]
    public void CanonicalizePreservesArrayOrder()
    {
        const string input = /*lang=json,strict*/ """{"arr":["z","a","m"]}""";

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ """{"arr":["z","a","m"]}""", result);
    }


    [TestMethod]
    public void CanonicalizeHandlesEmptyObject()
    {
        const string input = /*lang=json,strict*/ """{}""";

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ "{}", result);
    }


    [TestMethod]
    public void CanonicalizeHandlesEmptyArray()
    {
        const string input = /*lang=json,strict*/ """{"arr":[]}""";

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ """{"arr":[]}""", result);
    }


    [TestMethod]
    public void CanonicalizeHandlesNull()
    {
        const string input = /*lang=json,strict*/ """{"value":null}""";

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ """{"value":null}""", result);
    }


    [TestMethod]
    public void CanonicalizeHandlesBooleans()
    {
        const string input = /*lang=json,strict*/ """{"t":true,"f":false}""";

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ """{"f":false,"t":true}""", result);
    }


    [TestMethod]
    public void CanonicalizeHandlesIntegerNumbers()
    {
        const string input = /*lang=json,strict*/ """{"num":42}""";

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ """{"num":42}""", result);
    }


    [TestMethod]
    public void CanonicalizeHandlesNegativeNumbers()
    {
        const string input = /*lang=json,strict*/ """{"num":-123}""";

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ """{"num":-123}""", result);
    }


    [TestMethod]
    public void CanonicalizeHandlesZero()
    {
        const string input = /*lang=json,strict*/ """{"num":0}""";

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ """{"num":0}""", result);
    }


    [TestMethod]
    public void CanonicalizeHandlesDecimalNumbers()
    {
        const string input = /*lang=json,strict*/ """{"num":3.14}""";

        var result = Jcs.Canonicalize(input);

        //Verify the number is preserved correctly.
        //Assert.Contains(substring, value) - checks if value contains substring.
        Assert.Contains("3.14", result, StringComparison.Ordinal);
    }


    [TestMethod]
    public void CanonicalizeHandlesUnicodeStrings()
    {
        const string input = /*lang=json,strict*/ """{"text":"Hello, 世界"}""";

        var result = Jcs.Canonicalize(input);

        Assert.AreEqual(/*lang=json,strict*/ """{"text":"Hello, 世界"}""", result);
    }


    [TestMethod]
    public void CanonicalizeHandlesEscapedCharacters()
    {
        const string input = /*lang=json,strict*/ """{"text":"line1\nline2"}""";

        var result = Jcs.Canonicalize(input);

        //Newline should be escaped.
        //Assert.Contains(substring, value) - checks if value contains substring.
        Assert.Contains("\\n", result, StringComparison.Ordinal);
    }


    [TestMethod]
    public void CanonicalizeToUtf8BytesReturnsCorrectBytes()
    {
        const string input = /*lang=json,strict*/ """{"a":"b"}""";

        var result = Jcs.CanonicalizeToUtf8Bytes(input);

        var expected = Encoding.UTF8.GetBytes(/*lang=json,strict*/ """{"a":"b"}""");
        CollectionAssert.AreEqual(expected, result);
    }


    [TestMethod]
    public void CanonicalizeJsonDocumentWorks()
    {
        const string input = /*lang=json,strict*/ """{"z":"last","a":"first"}""";
        using var document = JsonDocument.Parse(input);

        var result = Jcs.Canonicalize(document);

        Assert.AreEqual(/*lang=json,strict*/ """{"a":"first","z":"last"}""", result);
    }


    [TestMethod]
    public void CanonicalizeJsonElementWorks()
    {
        const string input = /*lang=json,strict*/ """{"z":"last","a":"first"}""";
        using var document = JsonDocument.Parse(input);

        var result = Jcs.Canonicalize(document.RootElement);

        Assert.AreEqual(/*lang=json,strict*/ """{"a":"first","z":"last"}""", result);
    }


    [TestMethod]
    public void CanonicalizeThrowsForNullString()
    {
        Assert.Throws<ArgumentNullException>(() => Jcs.Canonicalize((string)null!));
    }


    [TestMethod]
    public void CanonicalizeThrowsForInvalidJson()
    {
        Assert.Throws<JsonException>(() => Jcs.Canonicalize("not valid json"));
    }


    [TestMethod]
    public void CanonicalizeProducesDeterministicOutput()
    {
        const string input1 = /*lang=json,strict*/ """{"b":"2","a":"1","c":"3"}""";
        const string input2 = /*lang=json,strict*/ """{"c":"3","a":"1","b":"2"}""";

        var result1 = Jcs.Canonicalize(input1);
        var result2 = Jcs.Canonicalize(input2);

        Assert.AreEqual(result1, result2);
        Assert.AreEqual(/*lang=json,strict*/ """{"a":"1","b":"2","c":"3"}""", result1);
    }


    [TestMethod]
    public void CanonicalizeHandlesComplexNestedStructure()
    {
        const string input = /*lang=json,strict*/ """
            {
                "credentials": [{
                    "type": "VerifiableCredential",
                    "issuer": "did:example:123"
                }],
                "@context": "https://www.w3.org/ns/credentials/v2",
                "id": "urn:uuid:12345"
            }
            """;

        var result = Jcs.Canonicalize(input);

        //Verify properties are sorted by checking that @context comes before credentials,
        //and credentials comes before id in the canonicalized output.
        var contextIndex = result.IndexOf("@context", StringComparison.Ordinal);
        var credentialsIndex = result.IndexOf("credentials", StringComparison.Ordinal);
        var idIndex = result.IndexOf("\"id\"", StringComparison.Ordinal);

        //Assert.IsLessThan(upperBound, value) asserts value < upperBound.
        Assert.IsLessThan(credentialsIndex, contextIndex, "@context should come before credentials.");
        Assert.IsLessThan(idIndex, credentialsIndex, "credentials should come before id.");

        //Verify nested object properties are also sorted.
        var issuerIndex = result.IndexOf("issuer", StringComparison.Ordinal);
        var typeIndex = result.IndexOf("type", StringComparison.Ordinal);
        Assert.IsLessThan(typeIndex, issuerIndex, "issuer should come before type in nested object.");
    }


    [TestMethod]
    public void SerializeObjectProducesCanonicalOutput()
    {
        var obj = new TestObject
        {
            Zebra = "last",
            Alpha = "first",
            Middle = "middle"
        };

        var result = Jcs.Serialize(obj);

        //Properties should be sorted alphabetically regardless of declaration order.
        Assert.AreEqual(/*lang=json,strict*/ """{"alpha":"first","middle":"middle","zebra":"last"}""", result);
    }


    [TestMethod]
    public void SerializeToUtf8BytesProducesCanonicalOutput()
    {
        var obj = new TestObject
        {
            Zebra = "last",
            Alpha = "first",
            Middle = "middle"
        };

        var result = Jcs.SerializeToUtf8Bytes(obj);

        var expected = Encoding.UTF8.GetBytes(/*lang=json,strict*/ """{"alpha":"first","middle":"middle","zebra":"last"}""");
        CollectionAssert.AreEqual(expected, result);
    }


    [TestMethod]
    public void SerializeThrowsForNullValue()
    {
        Assert.Throws<ArgumentNullException>(() => Jcs.Serialize<object>(null!));
    }


    [TestMethod]
    public void SerializeWithCustomOptionsPreservesEncoder()
    {
        var obj = new { text = "Hello, 世界" };
        var options = new JsonSerializerOptions
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        var result = Jcs.Serialize(obj, options);

        Assert.AreEqual(/*lang=json,strict*/ """{"text":"Hello, 世界"}""", result);
    }


    [TestMethod]
    public void SerializeNestedObjectsSortsAllLevels()
    {
        var obj = new
        {
            outer = new
            {
                z = "last",
                a = "first"
            },
            inner = "value"
        };

        var result = Jcs.Serialize(obj);

        //Both outer properties and nested properties should be sorted.
        Assert.AreEqual(/*lang=json,strict*/ """{"inner":"value","outer":{"a":"first","z":"last"}}""", result);
    }


    private sealed class TestObject
    {
        [JsonPropertyName("zebra")]
        public string? Zebra { get; set; }

        [JsonPropertyName("alpha")]
        public string? Alpha { get; set; }

        [JsonPropertyName("middle")]
        public string? Middle { get; set; }
    }
}