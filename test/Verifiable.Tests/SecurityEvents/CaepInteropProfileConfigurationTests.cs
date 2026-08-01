using System.Collections.Generic;
using Verifiable.Core.SecurityEvents;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Tests for <see cref="CaepInteropProfile.IsConformantTransmitterConfiguration"/>: the receiver-side
/// gate that a Transmitter Configuration Metadata document meets the CAEP Interoperability Profile 1.0
/// §2.3 floor — every profile MUST-include member present, <c>spec_version</c> at <c>1_0</c> or greater
/// (§2.3.1), and <c>authorization_schemes</c> declaring the OAuth 2.0 scheme URN (§2.3.7).
/// </summary>
/// <remarks>
/// <see href="https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html">OpenID CAEP
/// Interoperability Profile 1.0, draft 01</see> — no Final text exists yet; draft 01 is the document
/// under public review. Every case drives the shipped predicate over a fully-modelled
/// <see cref="SsfTransmitterConfiguration"/>, never over hand-rolled JSON.
/// </remarks>
[TestClass]
internal sealed class CaepInteropProfileConfigurationTests
{
    /// <summary>The Transmitter Issuer Identifier every fixture carries.</summary>
    private const string Issuer = "https://transmitter.example/";


    /// <summary>
    /// A document that carries every §2.3 MUST-include member, a <c>1_0</c> <c>spec_version</c>, both
    /// delivery methods, and the OAuth 2.0 authorization scheme passes the profile floor.
    /// </summary>
    [TestMethod]
    public void AConfigurationSatisfyingEveryMetadataMustIsConformant()
    {
        Assert.IsTrue(CaepInteropProfile.IsConformantTransmitterConfiguration(ConformantConfiguration()));
    }


    /// <summary>
    /// §2.3.1 makes <c>spec_version</c> MUST-include with a value of <c>1_0</c> or greater. A value
    /// below that floor is not conformant, and the gate fails closed on it.
    /// </summary>
    [TestMethod]
    public void AConfigurationWhoseSpecVersionIsBelowOneZeroIsNotConformant()
    {
        SsfTransmitterConfiguration configuration = ConformantConfiguration() with { SpecVersion = "0_9" };

        Assert.IsFalse(CaepInteropProfile.IsConformantTransmitterConfiguration(configuration));
    }


    /// <summary>
    /// §2.3.1: an absent <c>spec_version</c> — the Shared Signals Framework default, which the base
    /// spec tolerates — does not meet the profile's MUST-include, so the gate fails closed.
    /// </summary>
    [TestMethod]
    public void AConfigurationWithNoSpecVersionIsNotConformant()
    {
        SsfTransmitterConfiguration configuration = ConformantConfiguration() with { SpecVersion = null };

        Assert.IsFalse(CaepInteropProfile.IsConformantTransmitterConfiguration(configuration));
    }


    /// <summary>
    /// §2.3.1: a value with a <c>1_0</c>-or-greater numeric prefix followed by an SSF
    /// interoperability-draft suffix (<c>1_0-ID2</c>) is still conformant — the suffix does not
    /// lower the version below the floor.
    /// </summary>
    [TestMethod]
    public void AConfigurationWhoseSpecVersionCarriesAnInteropDraftSuffixIsConformant()
    {
        SsfTransmitterConfiguration configuration = ConformantConfiguration() with { SpecVersion = "1_0-ID2" };

        Assert.IsTrue(CaepInteropProfile.IsConformantTransmitterConfiguration(configuration));
    }


    /// <summary>
    /// §2.3.2 makes <c>delivery_methods_supported</c> MUST-include. A document that omits it does not
    /// meet the profile floor.
    /// </summary>
    [TestMethod]
    public void AConfigurationMissingDeliveryMethodsIsNotConformant()
    {
        SsfTransmitterConfiguration configuration = ConformantConfiguration() with { DeliveryMethodsSupported = null };

        Assert.IsFalse(CaepInteropProfile.IsConformantTransmitterConfiguration(configuration));
    }


    /// <summary>
    /// §2.3.6 makes <c>verification_endpoint</c> MUST-include. A document that omits it does not meet
    /// the profile floor.
    /// </summary>
    [TestMethod]
    public void AConfigurationMissingTheVerificationEndpointIsNotConformant()
    {
        SsfTransmitterConfiguration configuration = ConformantConfiguration() with { VerificationEndpoint = null };

        Assert.IsFalse(CaepInteropProfile.IsConformantTransmitterConfiguration(configuration));
    }


    /// <summary>
    /// §2.3.7 makes <c>authorization_schemes</c> MUST-include and pins its value to include the OAuth
    /// 2.0 scheme URN. A document whose schemes name only some other protocol does not meet the floor.
    /// </summary>
    [TestMethod]
    public void AConfigurationWhoseAuthorizationSchemesOmitOAuth2IsNotConformant()
    {
        SsfTransmitterConfiguration configuration = ConformantConfiguration() with
        {
            AuthorizationSchemes = [new SsfAuthorizationScheme { SpecUrn = "urn:example:scheme" }]
        };

        Assert.IsFalse(CaepInteropProfile.IsConformantTransmitterConfiguration(configuration));
    }


    /// <summary>A Transmitter Configuration Metadata document meeting every profile §2.3 MUST.</summary>
    /// <returns>The conformant fixture.</returns>
    private static SsfTransmitterConfiguration ConformantConfiguration() => new()
    {
        SpecVersion = "1_0",
        Issuer = Issuer,
        JwksUri = Issuer + "jwks",
        ConfigurationEndpoint = Issuer + "ssf/streams",
        StatusEndpoint = Issuer + "ssf/status",
        VerificationEndpoint = Issuer + "ssf/verify",
        DeliveryMethodsSupported = [SsfDeliveryMethods.PushHttp, SsfDeliveryMethods.PollHttp],
        AuthorizationSchemes = new List<SsfAuthorizationScheme>
        {
            new() { SpecUrn = SsfMetadataParameterNames.AuthorizationSchemeSpecUrnOAuth2 }
        }
    };
}
