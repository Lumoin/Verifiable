using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

[TestClass]
internal sealed class WellKnownPathsTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void OAuthAuthorizationServerRootIssuerProducesWellKnownSuffix()
    {
        Uri result = WellKnownPaths.OAuthAuthorizationServer.ComputeUri("https://example.com");

        Assert.AreEqual("https://example.com/.well-known/oauth-authorization-server", result.ToString());
    }

    [TestMethod]
    public void OAuthAuthorizationServerRootIssuerWithTrailingSlashProducesWellKnownSuffix()
    {
        Uri result = WellKnownPaths.OAuthAuthorizationServer.ComputeUri("https://example.com/");

        Assert.AreEqual("https://example.com/.well-known/oauth-authorization-server", result.ToString());
    }

    [TestMethod]
    public void OAuthAuthorizationServerPathIssuerInsertsWellKnownBeforePath()
    {
        Uri result = WellKnownPaths.OAuthAuthorizationServer.ComputeUri("https://example.com/tenant1");

        Assert.AreEqual("https://example.com/.well-known/oauth-authorization-server/tenant1", result.ToString());
    }

    [TestMethod]
    public void OAuthAuthorizationServerDeepPathIssuerInsertsWellKnownBeforePath()
    {
        Uri result = WellKnownPaths.OAuthAuthorizationServer.ComputeUri("https://example.com/region/eu/tenant1");

        Assert.AreEqual("https://example.com/.well-known/oauth-authorization-server/region/eu/tenant1", result.ToString());
    }

    [TestMethod]
    public void OAuthAuthorizationServerThrowsForEmptyIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WellKnownPaths.OAuthAuthorizationServer.ComputeUri(string.Empty));
    }

    [TestMethod]
    public void OAuthAuthorizationServerThrowsForWhitespaceIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WellKnownPaths.OAuthAuthorizationServer.ComputeUri("   "));
    }

    [TestMethod]
    public void OpenIdConfigurationRootIssuerProducesWellKnownSuffix()
    {
        Uri result = WellKnownPaths.OpenIdConfiguration.ComputeUri("https://example.com");

        Assert.AreEqual("https://example.com/.well-known/openid-configuration", result.ToString());
    }

    [TestMethod]
    public void OpenIdConfigurationPathIssuerAppendsSuffixAtEnd()
    {
        Uri result = WellKnownPaths.OpenIdConfiguration.ComputeUri("https://example.com/tenant1");

        Assert.AreEqual("https://example.com/tenant1/.well-known/openid-configuration", result.ToString());
    }

    [TestMethod]
    public void OpenIdConfigurationIgnoresTrailingSlash()
    {
        Uri result = WellKnownPaths.OpenIdConfiguration.ComputeUri("https://example.com/");

        Assert.AreEqual("https://example.com/.well-known/openid-configuration", result.ToString());
    }

    [TestMethod]
    public void OpenIdFederationProducesCorrectWellKnownSuffix()
    {
        Uri result = WellKnownPaths.OpenIdFederation.ComputeUri("https://trust-anchor.example.eu");

        Assert.AreEqual("https://trust-anchor.example.eu/.well-known/openid-federation", result.ToString());
    }

    [TestMethod]
    public void OpenIdFederationPathEntityIdentifierAppendsSuffixAtEnd()
    {
        Uri result = WellKnownPaths.OpenIdFederation.ComputeUri("https://example.com/entity/leaf");

        Assert.AreEqual("https://example.com/entity/leaf/.well-known/openid-federation", result.ToString());
    }

    [TestMethod]
    public void AuthZenConfigurationProducesCorrectWellKnownSuffix()
    {
        Uri result = WellKnownPaths.AuthZenConfiguration.ComputeUri("https://pdp.example.com");

        Assert.AreEqual("https://pdp.example.com/.well-known/authzen-configuration", result.ToString());
    }

    [TestMethod]
    public void DidWebRootDomainProducesWellKnownDidJson()
    {
        Uri result = WellKnownPaths.DidWeb.ComputeUri("did:web:example.com");

        Assert.AreEqual("https://example.com/.well-known/did.json", result.ToString());
    }

    [TestMethod]
    public void DidWebWithPathProducesPathDidJson()
    {
        Uri result = WellKnownPaths.DidWeb.ComputeUri("did:web:example.com:users:alice");

        Assert.AreEqual("https://example.com/users/alice/did.json", result.ToString());
    }

    [TestMethod]
    public void DidWebWithPortAndPathDecodesPercentEncodedColon()
    {
        Uri result = WellKnownPaths.DidWeb.ComputeUri("did:web:example.com%3A8443:users:bob");

        Assert.AreEqual("https://example.com:8443/users/bob/did.json", result.ToString());
    }

    [TestMethod]
    public void DidWebThrowsForNonDidWebIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WellKnownPaths.DidWeb.ComputeUri("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"));
    }

    [TestMethod]
    public void DidWebThrowsForEmptyIdentifier()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WellKnownPaths.DidWeb.ComputeUri(string.Empty));
    }

    [TestMethod]
    public void OAuthAuthorizationServerHasCorrectNameAndSpecReference()
    {
        Assert.AreEqual("oauth-authorization-server", WellKnownPaths.OAuthAuthorizationServer.Name);
        Assert.AreEqual("RFC 8414", WellKnownPaths.OAuthAuthorizationServer.SpecificationReference);
    }

    [TestMethod]
    public void OpenIdConfigurationHasCorrectNameAndSpecReference()
    {
        Assert.AreEqual("openid-configuration", WellKnownPaths.OpenIdConfiguration.Name);
        Assert.AreEqual("OpenID Connect Discovery 1.0", WellKnownPaths.OpenIdConfiguration.SpecificationReference);
    }

    [TestMethod]
    public void OpenIdFederationHasCorrectNameAndSpecReference()
    {
        Assert.AreEqual("openid-federation", WellKnownPaths.OpenIdFederation.Name);
        Assert.AreEqual("OpenID Federation 1.0", WellKnownPaths.OpenIdFederation.SpecificationReference);
    }

    [TestMethod]
    public void AuthZenConfigurationHasCorrectNameAndSpecReference()
    {
        Assert.AreEqual("authzen-configuration", WellKnownPaths.AuthZenConfiguration.Name);
        Assert.AreEqual("Authorization API 1.0", WellKnownPaths.AuthZenConfiguration.SpecificationReference);
    }

    [TestMethod]
    public void DidWebHasCorrectNameAndSpecReference()
    {
        Assert.AreEqual("did-web", WellKnownPaths.DidWeb.Name);
        Assert.AreEqual("did:web Method Specification", WellKnownPaths.DidWeb.SpecificationReference);
    }
}
