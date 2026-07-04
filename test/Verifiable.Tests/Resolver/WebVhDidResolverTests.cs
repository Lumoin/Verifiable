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


    /// <summary>
    /// A path segment that is ALREADY percent-encoded is canonicalized (percent-decoded, then re-encoded), not
    /// double-encoded: the did:webvh transform percent-decodes, validates, then re-encodes each segment, so an
    /// already-encoded segment is idempotent (did:webvh v1.0, The DID to HTTPS Transformation).
    /// </summary>
    [TestMethod]
    public void ResolveLogUrlCanonicalizesAlreadyEncodedPathSegment()
    {
        Assert.AreEqual(
            "https://example.com/%E7%94%A8%E6%88%B7/did.jsonl",
            WebVhDidResolver.Resolve("did:webvh:QmScid:example.com:%E7%94%A8%E6%88%B7"));
    }


    /// <summary>An internationalized domain with a percent-encoded (%3A) port keeps the port and IDNA-encodes only the host.</summary>
    [TestMethod]
    public void ResolveLogUrlIdnaDomainWithPortKeepsPort()
    {
        Assert.AreEqual(
            "https://xn--fsq.jp:3000/dids/issuer/did.jsonl",
            WebVhDidResolver.Resolve("did:webvh:QmScid:例.jp%3A3000:dids:issuer"));
    }


    /// <summary>
    /// The did:webvh transform inherits the did:web host and path-segment rules (it "otherwise mirrors the
    /// did:web location rules"): the host MUST be a domain name, so an IP-literal host is rejected; and a path
    /// segment MUST name a single component, so a dot-segment, an encoded path separator (<c>%2F</c>), or an
    /// empty segment is rejected — it would otherwise re-target the DID Log location, escaping the DID's
    /// designated path (did:webvh v1.0, DID-to-HTTPS Transformation; the shared host/segment guards).
    /// </summary>
    [TestMethod]
    [DataRow("did:webvh:QmScid:127.0.0.1")]                 //IPv4-literal host.
    [DataRow("did:webvh:QmScid:127.0.0.1%3A3000")]          //IPv4-literal host with a %3A-encoded port.
    [DataRow("did:webvh:QmScid:192.168.1.1:dids:issuer")]   //Private IPv4-literal host.
    [DataRow("did:webvh:QmScid:example.com:..")]            //Literal parent dot-segment (path traversal).
    [DataRow("did:webvh:QmScid:example.com:%2E%2E")]        //Percent-encoded parent dot-segment.
    [DataRow("did:webvh:QmScid:example.com:a%2Fb")]         //Segment carrying an encoded path separator.
    [DataRow("did:webvh:QmScid:example.com:.")]             //Literal current dot-segment.
    public void RejectsIpHostAndUnsafePathSegment(string did)
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebVhDidResolver.Resolve(did));
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
