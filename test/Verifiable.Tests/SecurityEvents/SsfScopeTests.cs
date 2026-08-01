using Verifiable.OAuth;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Tests for the Shared Signals scopes of CAEP Interoperability Profile 1.0
/// §2.7.3 in <see cref="WellKnownScopes"/> — the fixed-scope fallback a Receiver
/// uses when the Transmitter publishes no RFC 9728 protected-resource metadata.
/// </summary>
/// <remarks>
/// <see href="https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html">OpenID
/// CAEP Interoperability Profile 1.0, draft 01</see> — no Final text exists; draft 01 is the
/// document under public review. §2.7.2 is a different clause (the SSF Transmitter as a
/// Resource Server); the OAuth scopes are §2.7.3.
/// </remarks>
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
        //ssf.manage includes all ssf.read permissions (profile §2.7.3)…
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
        //Granular ssf.manage.* scopes are this library's own convention, not the
        //profile's: profile §2.7.3 defines only ssf.read and ssf.manage. The
        //convention is that a broad manage grant satisfies a granular management
        //requirement…
        Assert.IsTrue(WellKnownScopes.SsfScopeSatisfies(WellKnownScopes.SsfManage, "ssf.manage.create"));
        //…but a granular grant never satisfies a broader requirement.
        Assert.IsFalse(WellKnownScopes.SsfScopeSatisfies("ssf.manage.create", WellKnownScopes.SsfManage));
        Assert.IsFalse(WellKnownScopes.SsfScopeSatisfies("ssf.manage.create", WellKnownScopes.SsfRead));
    }
}
