using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Core.Did.Methods.WebVh;
using Verifiable.Core.Resolvers;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Tests for <see cref="Verifiable.Json.Converters.DidDocumentMetadataConverter"/>: the DID Resolution
/// document metadata is a flat open map, so the typed fields and the open-world
/// <see cref="DidDocumentMetadata.AdditionalData"/> (method-specific properties such as did:webvh's
/// <c>watchers</c>) are top-level members, unknown properties round-trip through the bucket, and there is no
/// nested <c>additionalData</c> member or type discriminator.
/// </summary>
[TestClass]
internal sealed class DidDocumentMetadataConverterTests
{
    private static JsonSerializerOptions Options { get; } = TestSetup.DefaultSerializationOptions;


    [TestMethod]
    public void MethodSpecificMetadataFlattensAtRoot()
    {
        DidDocumentMetadata metadata = new()
        {
            VersionId = "1-abc",
            AdditionalData = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WebVhResolutionMetadata.WatchersKey] = new List<object> { "https://watcher.example/watch" }
            }
        };

        string json = JsonSerializerExtensions.Serialize(metadata, Options);

        using JsonDocument document = JsonDocument.Parse(json);
        Assert.IsTrue(document.RootElement.TryGetProperty("versionId", out JsonElement versionId));
        Assert.AreEqual("1-abc", versionId.GetString());
        Assert.IsTrue(document.RootElement.TryGetProperty("watchers", out JsonElement watchers), "Method-specific watchers MUST flatten at the metadata root.");
        Assert.AreEqual(1, watchers.GetArrayLength());
        Assert.AreEqual("https://watcher.example/watch", watchers[0].GetString());
        Assert.IsFalse(document.RootElement.TryGetProperty("additionalData", out _), "The bucket MUST NOT surface as a nested 'additionalData' member.");
    }


    [TestMethod]
    public void UnknownPropertiesRoundTripThroughAdditionalData()
    {
        const string json = /*lang=json,strict*/ """
            {
                "versionId": "1-abc",
                "deactivated": false,
                "witness": { "threshold": 1, "witnesses": [{ "id": "did:key:zAbc" }] },
                "ttl": 3600
            }
            """;

        DidDocumentMetadata metadata = JsonSerializerExtensions.Deserialize<DidDocumentMetadata>(json, Options)!;

        Assert.AreEqual("1-abc", metadata.VersionId);
        Assert.IsNotNull(metadata.AdditionalData);
        Assert.IsTrue(metadata.AdditionalData!.ContainsKey("witness"), "Unknown metadata properties MUST land in AdditionalData.");
        Assert.IsTrue(metadata.AdditionalData.ContainsKey("ttl"));

        string reserialized = JsonSerializerExtensions.Serialize(metadata, Options);

        using JsonDocument document = JsonDocument.Parse(reserialized);
        Assert.IsTrue(document.RootElement.TryGetProperty("witness", out _), "Unknown properties MUST round-trip flattened at the root.");
        Assert.IsTrue(document.RootElement.TryGetProperty("ttl", out JsonElement ttl));
        Assert.AreEqual(3600, ttl.GetInt32());
        Assert.IsFalse(document.RootElement.TryGetProperty("additionalData", out _));
    }


    [TestMethod]
    public void WatchersDeserializeReadableViaAccessor()
    {
        const string json = /*lang=json,strict*/ """
            { "versionId": "1-abc", "watchers": ["https://w1.example", "https://w2.example"] }
            """;

        DidDocumentMetadata metadata = JsonSerializerExtensions.Deserialize<DidDocumentMetadata>(json, Options)!;

        IReadOnlyList<string> watchers = metadata.GetWatchers();
        Assert.HasCount(2, watchers);
        Assert.AreEqual("https://w1.example", watchers[0]);
        Assert.AreEqual("https://w2.example", watchers[1]);
    }


    [TestMethod]
    public void TypedFieldsRoundTrip()
    {
        DidDocumentMetadata metadata = new() { VersionId = "2-def", Deactivated = true };

        string json = JsonSerializerExtensions.Serialize(metadata, Options);
        DidDocumentMetadata roundTripped = JsonSerializerExtensions.Deserialize<DidDocumentMetadata>(json, Options)!;

        Assert.AreEqual("2-def", roundTripped.VersionId);
        Assert.IsTrue(roundTripped.Deactivated);
    }
}
