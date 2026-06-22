using Verifiable.Core;
using Verifiable.Core.Resolvers;
using Verifiable.Core.Did.Methods.Cheqd;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="CheqdDidResolver"/> covering REST API URL computation and the
/// <see cref="DidMethodResolverDelegate"/>-compatible <c>ResolveAsync</c> method.
/// </summary>
[TestClass]
internal sealed class CheqdDidResolverTests
{
    //did:cheqd resolution only computes a URL — no network I/O — so a default context
    //suffices; it exists only to satisfy the SSRF-policy-carrying parameter.
    private static readonly ExchangeContext EmptyContext = new();

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void ResolveMainnetDid()
    {
        const string did = "did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY";
        string result = CheqdDidResolver.Resolve(did);

        Assert.AreEqual(
            $"https://resolver.cheqd.net/1.0/identifiers/{did}",
            result);
    }

    [TestMethod]
    public void ResolveTestnetDid()
    {
        const string did = "did:cheqd:testnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY";
        string result = CheqdDidResolver.Resolve(did);

        Assert.AreEqual(
            $"https://resolver.cheqd.net/1.0/identifiers/{did}",
            result);
    }

    [TestMethod]
    public void ResolveThrowsForNonCheqdIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            CheqdDidResolver.Resolve("did:web:example.com"));
    }

    [TestMethod]
    public void ResolveThrowsForEmptyString()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            CheqdDidResolver.Resolve(""));
    }

    [TestMethod]
    public void ResolveThrowsForNull()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            CheqdDidResolver.Resolve(null!));
    }

    [TestMethod]
    public async Task ResolveAsyncReturnsDocumentUrlKind()
    {
        const string did = "did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY";
        var result = await CheqdDidResolver.ResolveAsync(
            did,
            DidResolutionOptions.Empty,
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.DocumentUrl, result.Kind);
        Assert.IsNull(result.Document);
        Assert.AreEqual(
            $"https://resolver.cheqd.net/1.0/identifiers/{did}",
            result.DocumentUrl);
    }

    [TestMethod]
    public async Task ResolveAsyncCanBeRegisteredWithDidMethodSelectors()
    {
        //Verify the method group signature matches DidMethodResolverDelegate exactly.
        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (Verifiable.Core.Did.Methods.WellKnownDidMethodPrefixes.CheqdDidMethodPrefix,
             CheqdDidResolver.ResolveAsync)));

        const string did = "did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY";
        var result = await resolver.ResolveAsync(did, EmptyContext, cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual(DidResolutionKind.DocumentUrl, result.Kind);
        Assert.IsNotNull(result.DocumentUrl);
    }
}
