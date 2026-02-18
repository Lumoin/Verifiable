using Verifiable.Core.Resolvers;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebDidResolver"/> using W3C CCG test vectors from
/// <see href="https://w3c-ccg.github.io/did-method-web/#did-method-operations"/>.
/// </summary>
[TestClass]
internal sealed class WebDidResolverTests
{
    [TestMethod]
    public void ResolveDomainOnly()
    {
        string result = WebDidResolver.Resolve("did:web:w3c-ccg.github.io");

        Assert.AreEqual("https://w3c-ccg.github.io/.well-known/did.json", result);
    }

    [TestMethod]
    public void ResolveDomainAndPath()
    {
        string result = WebDidResolver.Resolve("did:web:w3c-ccg.github.io:user:alice");

        Assert.AreEqual("https://w3c-ccg.github.io/user/alice/did.json", result);
    }

    [TestMethod]
    public void ResolveDomainPortAndPath()
    {
        string result = WebDidResolver.Resolve("did:web:example.com%3A3000:user:alice");

        Assert.AreEqual("https://example.com:3000/user/alice/did.json", result);
    }

    [TestMethod]
    public void ResolveDomainWithPortOnly()
    {
        string result = WebDidResolver.Resolve("did:web:example.com%3A8443");

        Assert.AreEqual("https://example.com:8443/.well-known/did.json", result);
    }

    [TestMethod]
    public void ResolveThrowsForNonDidWebIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WebDidResolver.Resolve("did:key:z6Mk..."));
    }

    [TestMethod]
    public void ResolveThrowsForEmptyString()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WebDidResolver.Resolve(""));
    }

    [TestMethod]
    public void ResolveThrowsForNull()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            WebDidResolver.Resolve(null!));
    }
}