using System.Text.Json;

namespace Verifiable.Tests.TestInfrastructure
{
    /// <summary>
    /// Provides utility methods for testing JSON serialization and deserialization.
    /// </summary>
    public static class JsonTestingUtilities
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
            var comparer = new JsonElementComparer();
            using var originalDocument = JsonDocument.Parse(originalJson);
            using var reserializedDocument = JsonDocument.Parse(reserializedJson);

            return comparer.Equals(originalDocument.RootElement, reserializedDocument.RootElement);
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
    }
}
