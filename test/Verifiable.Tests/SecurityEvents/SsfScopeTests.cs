using Verifiable.OAuth;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Tests for the Shared Signals scopes of CAEP Interoperability Profile 1.0
/// §2.7.2 in <see cref="WellKnownScopes"/> — the fixed-scope fallback a Receiver
/// uses when the Transmitter publishes no RFC 9728 protected-resource metadata.
/// </summary>
[TestClass]
internal sealed class SsfScopeTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void SsfScopeValuesAreTheProfileConstants()
    {
        Assert.AreEqual("ssf.read", WellKnownScopes.SsfRead);
        Assert.AreEqual("ssf.manage", WellKnownScopes.SsfManage);
        Assert.IsTrue(WellKnownScopes.IsSsfRead(WellKnownScopes.SsfRead));
        Assert.IsTrue(WellKnownScopes.IsSsfManage(WellKnownScopes.SsfManage));
        Assert.IsFalse(WellKnownScopes.IsSsfRead(WellKnownScopes.SsfManage));
    }


    [TestMethod]
    public void ManageSatisfiesReadButNotTheReverse()
    {
        //ssf.manage includes all ssf.read permissions (profile §2.7.2)…
        Assert.IsTrue(WellKnownScopes.SsfScopeSatisfies(WellKnownScopes.SsfManage, WellKnownScopes.SsfRead));
        //…but a read-only grant never satisfies a manage requirement.
        Assert.IsFalse(WellKnownScopes.SsfScopeSatisfies(WellKnownScopes.SsfRead, WellKnownScopes.SsfManage));
    }


    [TestMethod]
    public void ExactMatchesAndGranularManagePostfixesSatisfy()
    {
        Assert.IsTrue(WellKnownScopes.SsfScopeSatisfies(WellKnownScopes.SsfRead, WellKnownScopes.SsfRead));
        Assert.IsTrue(WellKnownScopes.SsfScopeSatisfies(WellKnownScopes.SsfManage, WellKnownScopes.SsfManage));
        Assert.IsTrue(WellKnownScopes.SsfScopeSatisfies("ssf.manage.create", "ssf.manage.create"));
        //Every management API operation MUST accept ssf.manage (profile §2.7.2), so a
        //broad manage grant satisfies a granular management requirement…
        Assert.IsTrue(WellKnownScopes.SsfScopeSatisfies(WellKnownScopes.SsfManage, "ssf.manage.create"));
        //…but a granular grant never satisfies a broader requirement.
        Assert.IsFalse(WellKnownScopes.SsfScopeSatisfies("ssf.manage.create", WellKnownScopes.SsfManage));
        Assert.IsFalse(WellKnownScopes.SsfScopeSatisfies("ssf.manage.create", WellKnownScopes.SsfRead));
    }
}
