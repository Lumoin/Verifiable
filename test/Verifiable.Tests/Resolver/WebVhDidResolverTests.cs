using System;
using Verifiable.Core.Did.Methods.WebVh;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebVhDidResolver.Resolve"/> — the <c>did:webvh</c> identifier to
/// <c>did.jsonl</c> DID Log URL transform, anchored on the worked examples in the did:webvh v1.0
/// specification (it drops the SCID segment and otherwise mirrors the <c>did:web</c> location rules).
/// </summary>
[TestClass]
internal sealed class WebVhDidResolverTests
{
    [TestMethod]
    [DataRow("did:webvh:QmScidExample:example.com", "https://example.com/.well-known/did.jsonl")]
    [DataRow("did:webvh:QmScidExample:issuer.example.com", "https://issuer.example.com/.well-known/did.jsonl")]
    [DataRow("did:webvh:QmScidExample:example.com:dids:issuer", "https://example.com/dids/issuer/did.jsonl")]
    [DataRow("did:webvh:QmScidExample:example.com%3A3000:dids:issuer", "https://example.com:3000/dids/issuer/did.jsonl")]
    public void ResolveLogUrlMatchesSpecificationExamples(string did, string expectedUrl)
    {
        Assert.AreEqual(expectedUrl, WebVhDidResolver.Resolve(did));
    }


    /// <summary>
    /// An internationalized domain MUST be IDNA/Punycode-encoded and each non-ASCII path segment MUST be
    /// percent-encoded per RFC3986 (did:webvh v1.0, DID-to-HTTPS Transformation).
    /// </summary>
    [TestMethod]
    [DataRow("did:webvh:QmScid:jp納豆.例.jp", "https://xn--jp-cd2fp15c.xn--fsq.jp/.well-known/did.jsonl")]
    [DataRow("did:webvh:QmScid:example.com:用户", "https://example.com/%E7%94%A8%E6%88%B7/did.jsonl")]
    [DataRow("did:webvh:QmScid:jp納豆.例.jp:用户", "https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl")]
    public void ResolveLogUrlAppliesIdnaAndPathEncoding(string did, string expectedUrl)
    {
        Assert.AreEqual(expectedUrl, WebVhDidResolver.Resolve(did));
    }


    /// <summary>An internationalized domain with a percent-encoded (%3A) port keeps the port and IDNA-encodes only the host.</summary>
    [TestMethod]
    public void ResolveLogUrlIdnaDomainWithPortKeepsPort()
    {
        Assert.AreEqual(
            "https://xn--fsq.jp:3000/dids/issuer/did.jsonl",
            WebVhDidResolver.Resolve("did:webvh:QmScid:例.jp%3A3000:dids:issuer"));
    }


    [TestMethod]
    public void RejectsNonWebVhIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebVhDidResolver.Resolve("did:web:example.com"));
    }


    [TestMethod]
    public void RejectsIdentifierWithoutDomain()
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebVhDidResolver.Resolve("did:webvh:QmScidExample"));
    }


    [TestMethod]
    public void RejectsNullOrWhitespace()
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebVhDidResolver.Resolve(string.Empty));
    }
}
