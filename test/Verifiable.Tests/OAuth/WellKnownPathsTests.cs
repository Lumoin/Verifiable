using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="WellKnownPaths"/> URL computation functions.
/// </summary>
[TestClass]
internal sealed class WellKnownPathsTests
{
    [TestMethod]
    public void OAuthAuthorizationServerRootIssuer()
    {
        Uri result = WellKnownPaths.OAuthAuthorizationServer.ComputeUri("https://example.com");

        Assert.AreEqual("https://example.com/.well-known/oauth-authorization-server", result.ToString());
    }

    [TestMethod]
    public void OAuthAuthorizationServerRootIssuerWithTrailingSlash()
    {
        Uri result = WellKnownPaths.OAuthAuthorizationServer.ComputeUri("https://example.com/");

        Assert.AreEqual("https://example.com/.well-known/oauth-authorization-server", result.ToString());
    }

    [TestMethod]
    public void OAuthAuthorizationServerWithPathComponent()
    {
        //RFC 8414 Section 3: path is moved after well-known.
        Uri result = WellKnownPaths.OAuthAuthorizationServer.ComputeUri("https://example.com/tenant1");

        Assert.AreEqual(
            "https://example.com/.well-known/oauth-authorization-server/tenant1",
            result.ToString());
    }

    [TestMethod]
    public void OAuthAuthorizationServerWithNestedPath()
    {
        Uri result = WellKnownPaths.OAuthAuthorizationServer.ComputeUri("https://example.com/org/tenant1");

        Assert.AreEqual(
            "https://example.com/.well-known/oauth-authorization-server/org/tenant1",
            result.ToString());
    }

    [TestMethod]
    public void OpenIdConfigurationRootIssuer()
    {
        Uri result = WellKnownPaths.OpenIdConfiguration.ComputeUri("https://example.com");

        Assert.AreEqual("https://example.com/.well-known/openid-configuration", result.ToString());
    }

    [TestMethod]
    public void OpenIdConfigurationWithPathAppendsSuffix()
    {
        //OpenID Connect Discovery appends, does not insert.
        Uri result = WellKnownPaths.OpenIdConfiguration.ComputeUri("https://example.com/issuer1");

        Assert.AreEqual(
            "https://example.com/issuer1/.well-known/openid-configuration",
            result.ToString());
    }

    [TestMethod]
    public void OpenIdFederationEntityConfiguration()
    {
        Uri result = WellKnownPaths.OpenIdFederation.ComputeUri("https://op.umu.se");

        Assert.AreEqual("https://op.umu.se/.well-known/openid-federation", result.ToString());
    }

    [TestMethod]
    public void AuthZenConfigurationPdpMetadata()
    {
        Uri result = WellKnownPaths.AuthZenConfiguration.ComputeUri("https://pdp.example.com");

        Assert.AreEqual("https://pdp.example.com/.well-known/authzen-configuration", result.ToString());
    }

    [TestMethod]
    public void DidWebDomainOnlyResolvesToWellKnown()
    {
        Uri result = WellKnownPaths.DidWeb.ComputeUri("did:web:example.com");

        Assert.AreEqual("https://example.com/.well-known/did.json", result.ToString());
    }

    [TestMethod]
    public void DidWebWithPathSegments()
    {
        Uri result = WellKnownPaths.DidWeb.ComputeUri("did:web:example.com:users:alice");

        Assert.AreEqual("https://example.com/users/alice/did.json", result.ToString());
    }

    [TestMethod]
    public void DidWebWithPortEncoding()
    {
        //Percent-encoded colon (%3A) in domain represents port separator.
        Uri result = WellKnownPaths.DidWeb.ComputeUri("did:web:example.com%3A8443");

        Assert.AreEqual("https://example.com:8443/.well-known/did.json", result.ToString());
    }

    [TestMethod]
    public void DidWebWithPortAndPath()
    {
        Uri result = WellKnownPaths.DidWeb.ComputeUri("did:web:example.com%3A8443:users:bob");

        Assert.AreEqual("https://example.com:8443/users/bob/did.json", result.ToString());
    }

    [TestMethod]
    public void DidWebThrowsForNonDidWebIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WellKnownPaths.DidWeb.ComputeUri("did:key:z6Mk..."));
    }

    [TestMethod]
    public void DidWebThrowsForEmptyIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WellKnownPaths.DidWeb.ComputeUri(""));
    }

    [TestMethod]
    public void OAuthAuthorizationServerThrowsForEmptyIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WellKnownPaths.OAuthAuthorizationServer.ComputeUri(""));
    }
}