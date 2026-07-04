using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Json;
using Verifiable.WebFinger;

namespace Verifiable.Tests.WebFinger;

/// <summary>
/// Regression tests for the WebFinger client hardening surfaced by the adversarial review: host-authority
/// validation in <see cref="WebFingerClient.ComputeQueryUri"/>, full user-part encoding in
/// <see cref="WebFingerClient.CreateAccountResource"/>, RFC 8288 §2.1.1 relation-type case handling in
/// <see cref="WebFingerClient.FindLinkHref"/>, and the SSRF-denial error taxonomy in
/// <see cref="WebFingerClient.BuildResolving"/>. Each test is the exploit that exposed the defect, kept as
/// the proof of its fix.
/// </summary>
[TestClass]
internal sealed class WebFingerHardeningTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A host that carries a userinfo <c>@</c> (authority confusion), or a <c>/</c>, <c>#</c>, <c>?</c>, or
    /// whitespace (path/query/fragment truncation), MUST be rejected rather than silently re-anchoring the
    /// connection or losing the §4 fixed path.
    /// </summary>
    [TestMethod]
    public void ComputeQueryUriRejectsAHostThatWouldReAnchorTheAuthorityOrTruncateThePath()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WebFingerClient.ComputeQueryUri("trusted.example.com@evil.example.com", "acct:alice@trusted.example.com", []));
        Assert.ThrowsExactly<ArgumentException>(() =>
            WebFingerClient.ComputeQueryUri("example.com/evil", "acct:alice@example.com", []));
        Assert.ThrowsExactly<ArgumentException>(() =>
            WebFingerClient.ComputeQueryUri("example.com#fragment", "acct:alice@example.com", []));
        Assert.ThrowsExactly<ArgumentException>(() =>
            WebFingerClient.ComputeQueryUri("example.com?query", "acct:alice@example.com", []));
        Assert.ThrowsExactly<ArgumentException>(() =>
            WebFingerClient.ComputeQueryUri("example.com evil", "acct:alice@example.com", []));
    }


    /// <summary>A bare authority — a reg-name, a host with a port, an IPv4 or bracketed IPv6 literal, an IDN A-label — is accepted and produces an https URI to that host with the fixed path and no userinfo.</summary>
    [TestMethod]
    public void ComputeQueryUriAcceptsBareAuthorities()
    {
        foreach(string host in new[] { "example.com", "sub.example.com", "example.com:8080", "127.0.0.1", "[::1]", "[::1]:8443", "xn--caf-dma.example" })
        {
            Uri uri = WebFingerClient.ComputeQueryUri(host, "acct:alice@example.com", []);

            Assert.AreEqual(Uri.UriSchemeHttps, uri.Scheme, $"'{host}' MUST resolve to an https query URI.");
            Assert.AreEqual(WellKnownWebFingerValues.WellKnownPath, uri.AbsolutePath, $"'{host}' MUST keep the well-known path.");
            Assert.IsTrue(string.IsNullOrEmpty(uri.UserInfo), $"'{host}' MUST NOT introduce userinfo.");
        }
    }


    /// <summary>RFC 8288 §2.1.1: a registered (bare-token) relation type is matched case-insensitively.</summary>
    [TestMethod]
    public void FindLinkHrefMatchesARegisteredRelationTypeCaseInsensitively()
    {
        JsonResourceDescriptor descriptor = new()
        {
            Links = [new WebFingerLink { Rel = "Self", Href = "https://example.com/actor" }]
        };

        Assert.AreEqual("https://example.com/actor", WebFingerClient.FindLinkHref(descriptor, "self"));
        Assert.AreEqual("https://example.com/actor", WebFingerClient.FindLinkHref(descriptor, "SELF"));
    }


    /// <summary>A URI relation type (one carrying a scheme) is matched case-sensitively per RFC 3986 §6.2.1.</summary>
    [TestMethod]
    public void FindLinkHrefMatchesAUriRelationTypeCaseSensitively()
    {
        JsonResourceDescriptor descriptor = new()
        {
            Links = [new WebFingerLink { Rel = "urn:webfinger:did", Href = "did:webs:example.com:x" }]
        };

        Assert.AreEqual("did:webs:example.com:x", WebFingerClient.FindLinkHref(descriptor, "urn:webfinger:did"));
        Assert.IsNull(WebFingerClient.FindLinkHref(descriptor, "URN:WEBFINGER:DID"),
            "A URI relation type differing only in case MUST NOT match.");
    }


    /// <summary>RFC 7565 §7: every user-part octet outside the unreserved set — a space, <c>:</c>, <c>/</c>, or a literal <c>@</c> — is percent-encoded; the §4 worked example still holds.</summary>
    [TestMethod]
    public void CreateAccountResourcePercentEncodesEveryReservedUserPartOctet()
    {
        Assert.AreEqual("acct:john%20doe@example.com", WebFingerClient.CreateAccountResource("john doe", "example.com"));
        Assert.AreEqual("acct:alice%3Abob@example.com", WebFingerClient.CreateAccountResource("alice:bob", "example.com"));
        Assert.AreEqual("acct:alice%2Fbob@example.com", WebFingerClient.CreateAccountResource("alice/bob", "example.com"));
        Assert.AreEqual("acct:juliet%40capulet.example@shoppingsite.example",
            WebFingerClient.CreateAccountResource("juliet@capulet.example", "shoppingsite.example"));
    }


    /// <summary>An account host carrying a stray <c>@</c> is rejected, so the trailing <c>@</c> unambiguously delimits the host.</summary>
    [TestMethod]
    public void CreateAccountResourceRejectsANonBareHost() =>
        Assert.ThrowsExactly<ArgumentException>(() => WebFingerClient.CreateAccountResource("alice", "evil.com@good.com"));


    /// <summary>
    /// A guarded-fetch policy denial (an SSRF block of a loopback target under the secure-default policy)
    /// surfaces as <see cref="WebFingerResolutionErrors.PolicyDenied"/>, distinct from a resource answering
    /// "not found" — and the transport is never reached.
    /// </summary>
    [TestMethod]
    public async Task AGuardedFetchPolicyDenialSurfacesAsPolicyDeniedNotNotFound()
    {
        OutboundTransportDelegate transport = (request, context, cancellationToken) =>
            throw new InvalidOperationException("the transport MUST NOT be reached when the policy denies the target");
        WebFingerResolveDelegate resolve = WebFingerClient.BuildResolving(transport, WebFingerJrdJsonParsing.ParseJrd);

        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        WebFingerResolutionResult result = await resolve(
            "acct:alice@127.0.0.1", "127.0.0.1", [], context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(WebFingerResolutionErrors.PolicyDenied, result.Error,
            "A policy denial (SSRF block) is a distinct outcome from a resource answering 'not found'.");
    }
}
