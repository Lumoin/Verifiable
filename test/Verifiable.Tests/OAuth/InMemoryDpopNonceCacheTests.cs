using Verifiable.OAuth.Dpop;

namespace Verifiable.Tests.OAuth;

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
}
