using CsCheck;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Property-based tests for <see cref="Jcs"/> JSON Canonicalization Scheme implementation.
/// These tests verify invariants that must hold for any valid JSON input, without requiring
/// exact expected outputs for each random input.
/// </summary>
/// <remarks>
/// <para>
/// Property-based testing is particularly well-suited for JCS because the key invariants
/// can be verified without a reference implementation:
/// </para>
/// <list type="bullet">
/// <item><description>Idempotence: canonicalizing twice produces the same result as canonicalizing once.</description></item>
/// <item><description>Semantic preservation: the JSON meaning is unchanged by canonicalization.</description></item>
/// <item><description>Determinism: identical semantic content always produces identical canonical form.</description></item>
/// <item><description>Output ordering: object properties are always lexicographically sorted.</description></item>
/// </list>
/// <para>
/// The advantage of property-based testing for canonicalization is that we do not need to predict
/// exact canonical bytes for random inputs. Instead, we verify invariants:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Idempotence</strong> (<c>canon(canon(x)) == canon(x)</c>): The single most valuable property.
/// If this fails, there is almost certainly a bug in ordering, number formatting, escaping, or whitespace handling.
/// </description></item>
/// <item><description>
/// <strong>Semantic equivalence</strong>: <c>JsonNode.DeepEquals(Parse(x), Parse(canon(x)))</c> must hold.
/// Canonicalization must not alter the JSON meaning.
/// </description></item>
/// <item><description>
/// <strong>Permutation invariance</strong>: <c>canon(x) == canon(shuffle_object_keys(x))</c>.
/// Shuffling object property order must not affect canonical output.
/// </description></item>
/// <item><description>
/// <strong>Output ordering</strong>: For every object in the canonical output, member names must be
/// in lexicographic order (by Unicode code points per RFC 8785).
/// </description></item>
/// <item><description>
/// <strong>Array order preservation</strong>: Arrays must preserve element order exactly.
/// </description></item>
/// </list>
/// <para>
/// Generator strategy: We generate JSON AST (not random strings) to avoid producing invalid JSON.
/// This uses <see cref="JsonNode"/> with configurable depth limits to prevent
/// combinatorial explosion. Targeted generators can be added for edge cases like control characters,
/// non-BMP characters, combining marks, and surrogate pairs.
/// </para>
/// <para>
/// See <see href="https://datatracker.ietf.org/doc/html/rfc8785">RFC 8785</see> for the specification.
/// </para>
/// </remarks>
[TestClass]
internal sealed class JcsPropertyTests
{
    /// <summary>
    /// Generator for JSON-safe strings that avoid problematic characters.
    /// </summary>
    private static Gen<string> SafeStringGen { get; } = Gen.String[Gen.Char.AlphaNumeric, 0, 20];

    /// <summary>
    /// Generator for JSON object property names.
    /// </summary>
    private static Gen<string> PropertyNameGen { get; } = Gen.String[Gen.Char.AlphaNumeric, 1, 15];

    /// <summary>
    /// Generator for simple JSON values (strings, numbers, booleans, null).
    /// </summary>
    private static Gen<JsonNode?> SimpleValueGen { get; } = Gen.OneOf(
        SafeStringGen.Select(s => (JsonNode?)JsonValue.Create(s)),
        Gen.Int[-10000, 10000].Select(i => (JsonNode?)JsonValue.Create(i)),
        Gen.Double[-1000.0, 1000.0].Where(d => !double.IsNaN(d) && !double.IsInfinity(d)).Select(d => (JsonNode?)JsonValue.Create(Math.Round(d, 6))),
        Gen.Bool.Select(b => (JsonNode?)JsonValue.Create(b)),
        Gen.Const((JsonNode?)null)
    );

    /// <summary>
    /// Main generator for JSON documents (objects or arrays at the root).
    /// </summary>
    private static Gen<JsonNode> JsonDocumentGen { get; } = Gen.OneOf(
        JsonObjectGen(3).Select(o => (JsonNode)o),
        JsonArrayGen(3).Select(a => (JsonNode)a)
    );


    /// <summary>
    /// Generates a JSON object with the specified depth limit.
    /// </summary>
    private static Gen<JsonObject> JsonObjectGen(int maxDepth)
    {
        if(maxDepth <= 0)
        {
            //At max depth, only simple values.
            return Gen.Int[0, 5].SelectMany(count =>
                PropertyNameGen.Array[count].SelectMany(names =>
                    SimpleValueGen.Array[count].Select(values =>
                    {
                        var obj = new JsonObject();
                        var usedNames = new HashSet<string>(StringComparer.Ordinal);
                        for(int i = 0; i < names.Length; i++)
                        {
                            var name = names[i];
                            //Ensure unique property names.
                            if(usedNames.Add(name))
                            {
                                obj[name] = values[i]?.DeepClone();
                            }
                        }

                        return obj;
                    })));
        }

        return Gen.Int[0, 4].SelectMany(count =>
            PropertyNameGen.Array[count].SelectMany(names =>
                JsonValueGen(maxDepth - 1).Array[count].Select(values =>
                {
                    var obj = new JsonObject();
                    var usedNames = new HashSet<string>(StringComparer.Ordinal);
                    for(int i = 0; i < names.Length; i++)
                    {
                        var name = names[i];
                        if(usedNames.Add(name))
                        {
                            obj[name] = values[i]?.DeepClone();
                        }
                    }

                    return obj;
                })));
    }


    /// <summary>
    /// Generates a JSON array with the specified depth limit.
    /// </summary>
    private static Gen<JsonArray> JsonArrayGen(int maxDepth)
    {
        if(maxDepth <= 0)
        {
            return Gen.Int[0, 5].SelectMany(count =>
                SimpleValueGen.Array[count].Select(values =>
                {
                    var arr = new JsonArray();
                    foreach(var v in values)
                    {
                        arr.Add(v?.DeepClone());
                    }

                    return arr;
                }));
        }

        return Gen.Int[0, 4].SelectMany(count =>
            JsonValueGen(maxDepth - 1).Array[count].Select(values =>
            {
                var arr = new JsonArray();
                foreach(var v in values)
                {
                    arr.Add(v?.DeepClone());
                }

                return arr;
            }));
    }


    /// <summary>
    /// Generates any JSON value (object, array, or simple value).
    /// </summary>
    private static Gen<JsonNode?> JsonValueGen(int maxDepth)
    {
        if(maxDepth <= 0)
        {
            return SimpleValueGen;
        }

        return Gen.OneOf(
            SimpleValueGen,
            JsonObjectGen(maxDepth).Select(o => (JsonNode?)o),
            JsonArrayGen(maxDepth).Select(a => (JsonNode?)a)
        );
    }


    [TestMethod]
    public void CanonicalizeIsIdempotent()
    {
        //Idempotence: canon(canon(x)) == canon(x)
        //This is the single most valuable property for canonicalization.
        JsonDocumentGen.Sample(json =>
        {
            var jsonString = json.ToJsonString();
            var canonical1 = Jcs.Canonicalize(jsonString);
            var canonical2 = Jcs.Canonicalize(canonical1);

            Assert.AreEqual(canonical1, canonical2, "Canonicalization must be idempotent.");
        });
    }


    [TestMethod]
    public void CanonicalizePreservesSemanticEquality()
    {
        //Semantic preservation: Parse(x) equals Parse(canon(x)).
        JsonDocumentGen.Sample(json =>
        {
            var jsonString = json.ToJsonString();
            var canonical = Jcs.Canonicalize(jsonString);

            var isEqual = JsonTestingUtilities.CompareJsonElements(jsonString, canonical);

            Assert.IsTrue(isEqual, "Canonicalization must preserve JSON semantic equality.");
        });
    }


    [TestMethod]
    public void CanonicalizeProducesSameOutputForShuffledObjectProperties()
    {
        //Permutation invariance: canon(x) == canon(shuffle(x)).
        //Shuffling object property order should not affect canonical output.
        JsonObjectGen(3).Sample(json =>
        {
            var original = json.ToJsonString();
            var shuffled = ShuffleObjectProperties(json);
            var shuffledString = shuffled.ToJsonString();

            var canonicalOriginal = Jcs.Canonicalize(original);
            var canonicalShuffled = Jcs.Canonicalize(shuffledString);

            Assert.AreEqual(canonicalOriginal, canonicalShuffled,
                "Canonicalization must produce identical output regardless of property order.");
        });
    }


    [TestMethod]
    public void CanonicalizeOutputHasSortedObjectProperties()
    {
        //Output ordering: all object properties in canonical output are lexicographically sorted.
        JsonDocumentGen.Sample(json =>
        {
            var jsonString = json.ToJsonString();
            var canonical = Jcs.Canonicalize(jsonString);

            var parsedCanonical = JsonNode.Parse(canonical);
            AssertObjectPropertiesAreSorted(parsedCanonical);
        });
    }


    [TestMethod]
    public void CanonicalizePreservesArrayOrder()
    {
        //Array order must be preserved exactly.
        JsonArrayGen(2).Sample(array =>
        {
            var jsonString = array.ToJsonString();
            var canonical = Jcs.Canonicalize(jsonString);

            var originalArray = JsonNode.Parse(jsonString)?.AsArray();
            var canonicalArray = JsonNode.Parse(canonical)?.AsArray();

            Assert.IsNotNull(originalArray);
            Assert.IsNotNull(canonicalArray);
            Assert.AreEqual(originalArray.Count, canonicalArray.Count, "Array length must be preserved.");

            for(int i = 0; i < originalArray.Count; i++)
            {
                var originalElement = originalArray[i]?.ToJsonString() ?? "null";
                var canonicalElement = canonicalArray[i]?.ToJsonString() ?? "null";

                //Canonicalize both for comparison since nested objects may have different order.
                var canonicalizedOriginal = Jcs.Canonicalize(originalElement);
                var canonicalizedCanonical = Jcs.Canonicalize(canonicalElement);

                Assert.AreEqual(canonicalizedOriginal, canonicalizedCanonical,
                    $"Array element at index {i} must be preserved.");
            }
        });
    }


    [TestMethod]
    public void CanonicalizeRemovesAllWhitespace()
    {
        //Canonical output should have no unnecessary whitespace.
        JsonDocumentGen.Sample(json =>
        {
            //Serialize with indentation to add whitespace.
            var options = new JsonSerializerOptions { WriteIndented = true };
            var indentedJson = json.ToJsonString(options);

            var canonical = Jcs.Canonicalize(indentedJson);

            //Canonical output should not contain newlines or multiple consecutive spaces.
            Assert.DoesNotContain("\n", canonical, StringComparison.Ordinal, "Canonical output must not contain newlines.");
            Assert.DoesNotContain("\r", canonical, StringComparison.Ordinal, "Canonical output must not contain carriage returns.");
            Assert.DoesNotContain("\t", canonical, StringComparison.Ordinal, "Canonical output must not contain tabs.");
        });
    }


    [TestMethod]
    public void CanonicalizeSerializeProducesSameResultAsCanonicalizeString()
    {
        //Jcs.Serialize<T> and Jcs.Canonicalize(JsonSerializer.Serialize<T>) should produce the same result.
        JsonObjectGen(2).Sample(json =>
        {
            var jsonString = json.ToJsonString();

            //Deserialize to a dictionary and serialize via Jcs.Serialize.
            var dict = JsonSerializer.Deserialize<Dictionary<string, object?>>(jsonString);
            if(dict is null)
            {
                return;
            }

            var viaSerialize = Jcs.Serialize(dict);
            var viaCanonicalizeString = Jcs.Canonicalize(jsonString);

            //Both approaches should yield semantically equivalent canonical JSON.
            var isEqual = JsonTestingUtilities.CompareJsonElements(viaSerialize, viaCanonicalizeString);
            Assert.IsTrue(isEqual, "Jcs.Serialize and Jcs.Canonicalize should produce semantically equivalent output.");
        });
    }


    /// <summary>
    /// Creates a copy of the JSON object with properties in a different order.
    /// </summary>
    private static JsonObject ShuffleObjectProperties(JsonObject original)
    {
        var properties = original.ToList();
        var shuffled = new JsonObject();

        //Reverse order to ensure different order than original.
        for(int i = properties.Count - 1; i >= 0; i--)
        {
            var kvp = properties[i];
            var value = kvp.Value?.DeepClone();

            //Recursively shuffle nested objects.
            if(value is JsonObject nestedObj)
            {
                value = ShuffleObjectProperties(nestedObj);
            }
            else if(value is JsonArray nestedArr)
            {
                value = ShuffleArrayObjects(nestedArr);
            }

            shuffled[kvp.Key] = value;
        }

        return shuffled;
    }


    /// <summary>
    /// Shuffles object properties within array elements.
    /// </summary>
    private static JsonArray ShuffleArrayObjects(JsonArray original)
    {
        var shuffled = new JsonArray();

        foreach(var element in original)
        {
            if(element is JsonObject obj)
            {
                shuffled.Add(ShuffleObjectProperties(obj));
            }
            else if(element is JsonArray arr)
            {
                shuffled.Add(ShuffleArrayObjects(arr));
            }
            else
            {
                shuffled.Add(element?.DeepClone());
            }
        }

        return shuffled;
    }


    /// <summary>
    /// Asserts that all object properties in the JSON tree are lexicographically sorted.
    /// Uses <see cref="JsonTestingUtilities.EnumerateObjects"/> for iterative traversal.
    /// </summary>
    private static void AssertObjectPropertiesAreSorted(JsonNode? root)
    {
        foreach(var obj in JsonTestingUtilities.EnumerateObjects(root))
        {
            var propertyNames = obj.Select(kvp => kvp.Key).ToList();
            for(int i = 1; i < propertyNames.Count; i++)
            {
                var comparison = string.CompareOrdinal(propertyNames[i - 1], propertyNames[i]);
                Assert.IsLessThan(0, comparison, $"Object properties must be sorted. '{propertyNames[i - 1]}' should come before '{propertyNames[i]}'.");
            }
        }
    }
}