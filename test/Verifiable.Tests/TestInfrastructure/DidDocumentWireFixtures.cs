using System.Text.Json;
using Verifiable.Core.Model.Did;
using Verifiable.Json;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>Shared DID document JSON serialization for the peer DID and OID4VP DI-proof test corpus.</summary>
internal static class DidDocumentWireFixtures
{
    /// <summary>Serializes <paramref name="document"/> via <see cref="JsonSerializerExtensions.Serialize"/>.</summary>
    /// <param name="document">The DID document to serialize.</param>
    /// <param name="options">The serializer options; each caller supplies its own configured instance.</param>
    /// <returns>The serialized JSON text.</returns>
    internal static string SerializeDidDocument(DidDocument document, JsonSerializerOptions options) =>
        JsonSerializerExtensions.Serialize(document, options);
}
