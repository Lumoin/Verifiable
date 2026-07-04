using System;
using Verifiable.Core.Did.Methods.WebPlus;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebPlusDidResolver.Resolve"/> — the <c>did:webplus</c> identifier to
/// <c>did-documents.jsonl</c> microledger URL transform, anchored on the worked examples in the
/// did:webplus specification (LedgerDomain Draft v0.4, DID-to-URL Mapping).
/// </summary>
[TestClass]
internal sealed class WebPlusDidResolverTests
{
    //The root-self-hash from the specification's worked DID-to-URL Mapping examples.
    private const string RootSelfHash = "uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA";

    /// <summary>
    /// The DID-to-URL transform maps the colon-delimited method-specific id (host, optional %3A-encoded port,
    /// optional path, trailing root-self-hash) to the microledger URL, using <c>https</c> for a normal host
    /// (did:webplus Draft v0.4, DID-to-URL Mapping).
    /// </summary>
    [TestMethod]
    [DataRow(
        "did:webplus:example.com:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "https://example.com/uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA/did-documents.jsonl")]
    [DataRow(
        "did:webplus:example.com:path-component:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "https://example.com/path-component/uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA/did-documents.jsonl")]
    [DataRow(
        "did:webplus:example.com%3A3000:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "https://example.com:3000/uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA/did-documents.jsonl")]
    [DataRow(
        "did:webplus:example.com%3A3000:path-component:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "https://example.com:3000/path-component/uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA/did-documents.jsonl")]
    [DataRow(
        "did:webplus:example.com%3A3000:a:very:long:path:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "https://example.com:3000/a/very/long/path/uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA/did-documents.jsonl")]
    public void ResolveMicroledgerUrlMatchesSpecificationExamples(string did, string expectedUrl)
    {
        Assert.AreEqual(expectedUrl, WebPlusDidResolver.Resolve(did));
    }


    /// <summary>
    /// When the host is <c>localhost</c> the scheme is <c>http</c>, not <c>https</c>, to ease local testing
    /// during development (did:webplus Draft v0.4, DID-to-URL Mapping).
    /// </summary>
    [TestMethod]
    [DataRow(
        "did:webplus:localhost:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "http://localhost/uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA/did-documents.jsonl")]
    [DataRow(
        "did:webplus:localhost:path-component:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "http://localhost/path-component/uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA/did-documents.jsonl")]
    [DataRow(
        "did:webplus:localhost%3A3000:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "http://localhost:3000/uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA/did-documents.jsonl")]
    [DataRow(
        "did:webplus:localhost%3A3000:path-component:uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA",
        "http://localhost:3000/path-component/uHiBKHZUE3HHlYcyVIF-vPm0Xg71vqJla2L1OGXHMSK4NEA/did-documents.jsonl")]
    public void ResolveMicroledgerUrlUsesHttpForLocalhost(string did, string expectedUrl)
    {
        Assert.AreEqual(expectedUrl, WebPlusDidResolver.Resolve(did));
    }


    /// <summary>
    /// The did:webplus DID-to-URL mapping is a cousin of the did:web host and path rules: the host MUST be a
    /// domain name, so an IP-literal host is rejected; and a path segment MUST name a single component, so a
    /// dot-segment, an encoded path separator (<c>%2F</c>), or an empty segment is rejected — it would otherwise
    /// re-target the microledger location (did:webplus Draft v0.4, DID-to-URL Mapping; the shared host/segment guards).
    /// </summary>
    [TestMethod]
    [DataRow("did:webplus:127.0.0.1:" + RootSelfHash)]                    //IPv4-literal host.
    [DataRow("did:webplus:127.0.0.1%3A3000:" + RootSelfHash)]            //IPv4-literal host with a %3A-encoded port.
    [DataRow("did:webplus:192.168.1.1:path-component:" + RootSelfHash)]  //Private IPv4-literal host.
    [DataRow("did:webplus:example.com:..:" + RootSelfHash)]              //Literal parent dot-segment (path traversal).
    [DataRow("did:webplus:example.com:%2E%2E:" + RootSelfHash)]          //Percent-encoded parent dot-segment.
    [DataRow("did:webplus:example.com:a%2Fb:" + RootSelfHash)]           //Segment carrying an encoded path separator.
    public void RejectsIpHostAndUnsafePathSegment(string did)
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebPlusDidResolver.Resolve(did));
    }


    /// <summary>An identifier of a different DID method MUST be rejected.</summary>
    [TestMethod]
    public void RejectsNonWebPlusIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebPlusDidResolver.Resolve($"did:web:example.com:{RootSelfHash}"));
    }


    /// <summary>A host with no trailing root-self-hash segment MUST be rejected.</summary>
    [TestMethod]
    public void RejectsIdentifierWithoutRootSelfHash()
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebPlusDidResolver.Resolve("did:webplus:example.com"));
    }


    /// <summary>A null, empty or whitespace identifier MUST be rejected.</summary>
    [TestMethod]
    [DataRow("")]
    [DataRow("   ")]
    public void RejectsEmptyIdentifier(string did)
    {
        Assert.ThrowsExactly<ArgumentException>(() => WebPlusDidResolver.Resolve(did));
    }
}
