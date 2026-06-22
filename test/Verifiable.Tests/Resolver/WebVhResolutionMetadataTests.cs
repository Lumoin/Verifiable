using System;
using System.Collections.Generic;
using Verifiable.Core.Did.Methods.WebVh;
using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebVhResolutionMetadata"/> — the did:webvh resolution metadata carried in the
/// open-world <see cref="DidDocumentMetadata.AdditionalData"/> bucket and its strongly-typed read accessors.
/// </summary>
[TestClass]
internal sealed class WebVhResolutionMetadataTests
{
    private static DidDocumentMetadata WithMethodMetadata()
    {
        return new DidDocumentMetadata
        {
            VersionId = "1-x",
            AdditionalData = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WebVhResolutionMetadata.WatchersKey] = new List<object> { "https://w1.example", "https://w2.example" },
                [WebVhResolutionMetadata.ScidKey] = "QmScid",
                [WebVhResolutionMetadata.PortableKey] = true,
                [WebVhResolutionMetadata.TtlKey] = "3600",
                [WebVhResolutionMetadata.VersionTimeKey] = "2025-01-01T00:00:00Z"
            }
        };
    }


    [TestMethod]
    public void AccessorsReadTheBucket()
    {
        DidDocumentMetadata metadata = WithMethodMetadata();

        Assert.HasCount(2, metadata.GetWatchers());
        Assert.AreEqual("https://w1.example", metadata.GetWatchers()[0]);
        Assert.AreEqual("QmScid", metadata.GetScid());
        Assert.IsTrue(metadata.GetPortable()!.Value);
        Assert.AreEqual("3600", metadata.GetTtl());
        Assert.AreEqual("2025-01-01T00:00:00Z", metadata.GetVersionTime());
    }


    [TestMethod]
    public void AccessorsAreEmptyWhenAbsent()
    {
        DidDocumentMetadata metadata = new() { VersionId = "1-x" };

        Assert.IsEmpty(metadata.GetWatchers());
        Assert.IsNull(metadata.GetScid());
        Assert.IsNull(metadata.GetPortable());
        Assert.IsNull(metadata.GetTtl());
        Assert.IsNull(metadata.GetVersionTime());
    }


    /// <summary>The open-world bucket is flattened on the wire and is intentionally not part of equality.</summary>
    [TestMethod]
    public void AdditionalDataIsExcludedFromEquality()
    {
        DidDocumentMetadata withMethodMetadata = WithMethodMetadata();
        DidDocumentMetadata withoutMethodMetadata = new() { VersionId = "1-x" };

        Assert.IsTrue(withMethodMetadata == withoutMethodMetadata);
        Assert.IsTrue(withMethodMetadata.Equals(withoutMethodMetadata));
    }
}
