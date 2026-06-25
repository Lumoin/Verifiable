using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Tests for <see cref="EntityIdentifier"/> construction against the Entity
/// Identifier definition in OpenID Federation 1.0 §1.2: an https URL with a
/// host component, permitting port and path, forbidding query and fragment.
/// </summary>
[TestClass]
internal sealed class EntityIdentifierTests
{
    [TestMethod]
    public void HttpsUrlWithHostIsAccepted()
    {
        EntityIdentifier id = new("https://entity.example");

        Assert.AreEqual("https://entity.example", id.Value);
    }


    [TestMethod]
    public void HttpsUrlWithPortAndPathIsAccepted()
    {
        //§1.2: port and path components are permitted.
        EntityIdentifier id = new("https://entity.example:8443/federation/tenant-a");

        Assert.AreEqual("https://entity.example:8443/federation/tenant-a", id.Value);
    }


    [TestMethod]
    public void HttpSchemeIsRejected()
    {
        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(
            static () => new EntityIdentifier("http://entity.example"));

        Assert.Contains("https", ex.Message);
    }


    [TestMethod]
    public void NonHttpSchemeIsRejected()
    {
        //A non-http(s) absolute value (the cross-platform Uri.TryCreate trap) must be rejected.
        Assert.ThrowsExactly<ArgumentException>(
            static () => new EntityIdentifier("urn:example:entity"));
    }


    [TestMethod]
    public void RelativeValueIsRejected()
    {
        Assert.ThrowsExactly<ArgumentException>(
            static () => new EntityIdentifier("/federation/entity"));
    }


    [TestMethod]
    public void QueryComponentIsRejected()
    {
        //§1.2: an Entity Identifier MUST NOT contain a query component.
        Assert.ThrowsExactly<ArgumentException>(
            static () => new EntityIdentifier("https://entity.example?tenant=a"));
    }


    [TestMethod]
    public void FragmentComponentIsRejected()
    {
        //§1.2: an Entity Identifier MUST NOT contain a fragment component.
        Assert.ThrowsExactly<ArgumentException>(
            static () => new EntityIdentifier("https://entity.example#key-1"));
    }
}
