using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

[TestClass]
internal sealed class WellKnownScopesTests
{
    public TestContext TestContext { get; set; } = null!;


    //IsXxx single-value identity predicates.

    [TestMethod]
    public void IsOpenIdReturnsTrueForExactMatch()
    {
        Assert.IsTrue(WellKnownScopes.IsOpenId("openid"));
    }

    [TestMethod]
    public void IsOpenIdReturnsFalseForDifferentScope()
    {
        Assert.IsFalse(WellKnownScopes.IsOpenId("profile"),
            "IsOpenId must not match a different scope value.");
    }

    [TestMethod]
    public void IsOpenIdIsCaseSensitive()
    {
        Assert.IsFalse(WellKnownScopes.IsOpenId("OpenID"),
            "Scope comparison is case-sensitive per RFC 6749 §3.3.");
    }

    [TestMethod]
    public void IsProfileReturnsTrueForExactMatch()
    {
        Assert.IsTrue(WellKnownScopes.IsProfile("profile"));
    }

    [TestMethod]
    public void IsEmailReturnsTrueForExactMatch()
    {
        Assert.IsTrue(WellKnownScopes.IsEmail("email"));
    }

    [TestMethod]
    public void IsAddressReturnsTrueForExactMatch()
    {
        Assert.IsTrue(WellKnownScopes.IsAddress("address"));
    }

    [TestMethod]
    public void IsPhoneReturnsTrueForExactMatch()
    {
        Assert.IsTrue(WellKnownScopes.IsPhone("phone"));
    }

    [TestMethod]
    public void IsOfflineAccessReturnsTrueForExactMatch()
    {
        Assert.IsTrue(WellKnownScopes.IsOfflineAccess("offline_access"));
    }

    [TestMethod]
    public void IsVpTokenReturnsTrueForExactMatch()
    {
        Assert.IsTrue(WellKnownScopes.IsVpToken("vp_token"));
    }

    [TestMethod]
    public void IsCredentialIssuanceReturnsTrueForExactMatch()
    {
        Assert.IsTrue(WellKnownScopes.IsCredentialIssuance("credential"));
    }


    //ContainsScopeValue — presence in space-separated strings.

    [TestMethod]
    public void ContainsScopeValueReturnsTrueWhenScopeIsOnlyValue()
    {
        Assert.IsTrue(WellKnownScopes.ContainsScopeValue("openid", "openid"));
    }

    [TestMethod]
    public void ContainsScopeValueReturnsTrueWhenScopeIsFirstToken()
    {
        Assert.IsTrue(WellKnownScopes.ContainsScopeValue("openid profile email", "openid"));
    }

    [TestMethod]
    public void ContainsScopeValueReturnsTrueWhenScopeIsMiddleToken()
    {
        Assert.IsTrue(WellKnownScopes.ContainsScopeValue("openid profile email", "profile"));
    }

    [TestMethod]
    public void ContainsScopeValueReturnsTrueWhenScopeIsLastToken()
    {
        Assert.IsTrue(WellKnownScopes.ContainsScopeValue("openid profile email", "email"));
    }

    [TestMethod]
    public void ContainsScopeValueReturnsFalseWhenScopeAbsent()
    {
        Assert.IsFalse(WellKnownScopes.ContainsScopeValue("openid profile", "email"),
            "email is not present in the scope string.");
    }

    [TestMethod]
    public void ContainsScopeValueReturnsFalseForPartialMatch()
    {
        Assert.IsFalse(WellKnownScopes.ContainsScopeValue("openid profile", "open"),
            "A partial token match must not be accepted — open is not openid.");
    }

    [TestMethod]
    public void ContainsScopeValueReturnsFalseForEmptyScopeString()
    {
        Assert.IsFalse(WellKnownScopes.ContainsScopeValue(string.Empty, "openid"),
            "An empty scope string contains no values.");
    }

    [TestMethod]
    public void ContainsScopeValueIsCaseSensitive()
    {
        Assert.IsFalse(WellKnownScopes.ContainsScopeValue("OpenID Profile", "openid"),
            "Scope comparison is case-sensitive per RFC 6749 §3.3.");
    }

    [TestMethod]
    public void ContainsOpenIdReturnsTrueWhenPresentInMultipleScopes()
    {
        Assert.IsTrue(WellKnownScopes.ContainsOpenId("openid profile email offline_access"));
    }

    [TestMethod]
    public void ContainsVpTokenReturnsTrueWhenPresent()
    {
        Assert.IsTrue(WellKnownScopes.ContainsVpToken("openid vp_token"));
    }

    [TestMethod]
    public void ContainsOfflineAccessReturnsFalseWhenAbsent()
    {
        Assert.IsFalse(WellKnownScopes.ContainsOfflineAccess("openid profile"),
            "offline_access was not requested so must not be found.");
    }


    //GetCanonicalizedValue.

    [TestMethod]
    public void GetCanonicalizedValueReturnsConstantForOpenId()
    {
        Assert.AreEqual(WellKnownScopes.OpenId, WellKnownScopes.GetCanonicalizedValue("openid"));
    }

    [TestMethod]
    public void GetCanonicalizedValueReturnsConstantForOfflineAccess()
    {
        Assert.AreEqual(WellKnownScopes.OfflineAccess, WellKnownScopes.GetCanonicalizedValue("offline_access"));
    }

    [TestMethod]
    public void GetCanonicalizedValueReturnsConstantForVpToken()
    {
        Assert.AreEqual(WellKnownScopes.VpToken, WellKnownScopes.GetCanonicalizedValue("vp_token"));
    }

    [TestMethod]
    public void GetCanonicalizedValueReturnsOriginalForUnknownScope()
    {
        const string customScope = "read:documents";

        Assert.AreEqual(customScope, WellKnownScopes.GetCanonicalizedValue(customScope),
            "An unrecognized scope must be returned unchanged.");
    }

    [TestMethod]
    public void GetCanonicalizedValueReturnsOriginalForWrongCase()
    {
        Assert.AreEqual("OpenID", WellKnownScopes.GetCanonicalizedValue("OpenID"),
            "Wrong-case input is not a recognized scope and must be returned as-is.");
    }


}