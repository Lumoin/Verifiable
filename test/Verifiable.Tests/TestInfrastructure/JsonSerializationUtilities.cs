using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// Provides utility methods for testing JSON serialization and deserialization.
    /// </summary>
    internal static class JsonTestingUtilities
    {
        /// <summary>
        /// Performs a serialization and deserialization cycle on the provided JSON string.
        /// </summary>
        /// <typeparam name="TDocument">The type of the document to deserialize and serialize.</typeparam>
        /// <param name="inputJson">The input JSON string.</param>
        /// <param name="options">The JSON serializer options.</param>
        /// <returns>A tuple containing the deserialized object and the re-serialized string.</returns>
        public static (TDocument? DeserializedObject, string ReserializedString) PerformSerializationCycle<TDocument>(string inputJson, JsonSerializerOptions options)
        {
            var deserializedObject = JsonSerializer.Deserialize<TDocument>(inputJson, options);
            var reserializedString = JsonSerializer.Serialize(deserializedObject, options);

            return (deserializedObject, reserializedString);
        }


        /// <summary>
        /// Compares two JSON strings to determine if they represent the same JSON structure.
        /// </summary>
        /// <param name="originalJson">The original JSON string.</param>
        /// <param name="reserializedJson">The re-serialized JSON string.</param>
        /// <returns>True if the two JSON strings represent the same JSON structure; otherwise, false.</returns>
        public static bool CompareJsonElements(string originalJson, string reserializedJson)
        {
            var originalDocument = JsonNode.Parse(originalJson);
            var reserializedDocument = JsonNode.Parse(reserializedJson);

            return JsonNode.DeepEquals(originalDocument, reserializedDocument);
        }


        /// <summary>
        /// Performs a serialization and deserialization cycle on the provided JSON string for two different document types.
        /// </summary>
        /// <typeparam name="TDocument1">The type of the first document to deserialize and serialize.</typeparam>
        /// <typeparam name="TDocument2">The type of the second document to deserialize and serialize.</typeparam>
        /// <param name="inputJson">The input JSON string.</param>
        /// <param name="options">The JSON serializer options.</param>
        /// <returns>A tuple containing the deserialized objects and the re-serialized strings for both document types.</returns>
        public static (TDocument1? DeserializedObject1, TDocument2? DeserializedObject2, string ReserializedString1, string ReserializedString2)
            PerformExtendedSerializationCycle<TDocument1, TDocument2>(string inputJson, JsonSerializerOptions options)
        {
            var deserializedObject1 = JsonSerializer.Deserialize<TDocument1>(inputJson, options);
            var deserializedObject2 = JsonSerializer.Deserialize<TDocument2>(inputJson, options);
            var reserializedString1 = JsonSerializer.Serialize(deserializedObject1, options);
            var reserializedString2 = JsonSerializer.Serialize(deserializedObject2, options);

            return (deserializedObject1, deserializedObject2, reserializedString1, reserializedString2);
        }


        /// <summary>
        /// Enumerates all nodes in a JSON tree using iterative depth-first traversal.
        /// </summary>
        /// <param name="root">The root node of the JSON tree.</param>
        /// <returns>An enumerable of all nodes in the tree, including the root.</returns>
        /// <remarks>
        /// <para>
        /// This method uses an explicit stack instead of recursion to avoid call stack overhead.
        /// Since JSON is a tree structure (no cycles), no visited-node tracking is needed.
        /// </para>
        /// <para>
        /// Traversal order is depth-first but the specific order among siblings is not guaranteed.
        /// For validation purposes (checking all nodes satisfy some property), order does not matter.
        /// </para>
        /// </remarks>
        public static IEnumerable<JsonNode> EnumerateNodes(JsonNode? root)
        {
            if(root is null)
            {
                yield break;
            }

            var stack = new Stack<JsonNode>();
            stack.Push(root);

            while(stack.Count > 0)
            {
                var current = stack.Pop();
                yield return current;

                if(current is JsonObject obj)
                {
                    foreach(var kvp in obj)
                    {
                        if(kvp.Value is not null)
                        {
                            stack.Push(kvp.Value);
                        }
                    }
                }
                else if(current is JsonArray arr)
                {
                    foreach(var element in arr)
                    {
                        if(element is not null)
                        {
                            stack.Push(element);
                        }
                    }
                }
            }
        }


        /// <summary>
        /// Enumerates all objects in a JSON tree using iterative depth-first traversal.
        /// </summary>
        /// <param name="root">The root node of the JSON tree.</param>
        /// <returns>An enumerable of all <see cref="JsonObject"/> nodes in the tree.</returns>
        /// <remarks>
        /// This is a convenience method that filters <see cref="EnumerateNodes"/> to return only objects.
        /// Useful for validating properties across all objects in a JSON document.
        /// </remarks>
        public static IEnumerable<JsonObject> EnumerateObjects(JsonNode? root)
        {
            foreach(var node in EnumerateNodes(root))
            {
                if(node is JsonObject obj)
                {
                    yield return obj;
                }
            }
        }


        /// <summary>
        /// Enumerates all arrays in a JSON tree using iterative depth-first traversal.
        /// </summary>
        /// <param name="root">The root node of the JSON tree.</param>
        /// <returns>An enumerable of all <see cref="JsonArray"/> nodes in the tree.</returns>
        /// <remarks>
        /// This is a convenience method that filters <see cref="EnumerateNodes"/> to return only arrays.
        /// </remarks>
        public static IEnumerable<JsonArray> EnumerateArrays(JsonNode? root)
        {
            foreach(var node in EnumerateNodes(root))
            {
                if(node is JsonArray arr)
                {
                    yield return arr;
                }
            }
        }
    }
}