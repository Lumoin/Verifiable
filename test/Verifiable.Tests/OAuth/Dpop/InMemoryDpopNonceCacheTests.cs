using Verifiable.OAuth.Dpop;

namespace Verifiable.Tests.OAuth.Dpop;

[TestClass]
internal sealed class InMemoryDpopNonceCacheTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void LookupReturnsNullWhenNothingStored()
    {
        InMemoryDpopNonceCache cache = new();
        Assert.IsNull(cache.Lookup("https://as.example.com"));
    }


    [TestMethod]
    public void StoreThenLookupRoundTrips()
    {
        InMemoryDpopNonceCache cache = new();
        cache.Store("https://as.example.com", "nonce-abc");

        Assert.AreEqual("nonce-abc", cache.Lookup("https://as.example.com"));
    }


    [TestMethod]
    public void StoreOverwritesPreviousValueForSameAuthority()
    {
        InMemoryDpopNonceCache cache = new();
        cache.Store("https://as.example.com", "first");
        cache.Store("https://as.example.com", "second");

        Assert.AreEqual("second", cache.Lookup("https://as.example.com"));
    }


    [TestMethod]
    public void AuthorityForExtractsSchemeHostAndPort()
    {
        //RFC 9449 §10.1 keys nonces by the receiving authority. The cache's
        //authority key strips path, query, and fragment so the same nonce
        //applies across every endpoint at that origin.
        Assert.AreEqual(
            "https://as.example.com",
            InMemoryDpopNonceCache.AuthorityFor(new Uri("https://as.example.com/connect/abc/token")));

        Assert.AreEqual(
            "https://as.example.com:8443",
            InMemoryDpopNonceCache.AuthorityFor(new Uri("https://as.example.com:8443/par?x=1")));

        Assert.AreEqual(
            "http://localhost:5000",
            InMemoryDpopNonceCache.AuthorityFor(new Uri("http://localhost:5000/connect/x/token#frag")));
    }
}
