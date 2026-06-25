using Verifiable.OAuth;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Pins the <see cref="FederationMetadataParameterNames"/> endpoint metadata
/// keys to their exact OpenID Federation 1.0 §5.1.1 wire spellings. A typo in
/// any of these silently breaks interoperability — consumers look up the
/// spec-spelled key and find nothing — so each is asserted against the literal
/// from the specification.
/// </summary>
[TestClass]
internal sealed class FederationMetadataParameterNamesTests
{
    /// <summary>
    /// Each federation endpoint metadata key equals its Federation §5.1.1 wire name.
    /// </summary>
    [TestMethod]
    public void EndpointMetadataKeysMatchSpecWireNames()
    {
        Assert.AreEqual("federation_fetch_endpoint", FederationMetadataParameterNames.FetchEndpoint);
        Assert.AreEqual("federation_list_endpoint", FederationMetadataParameterNames.ListEndpoint);
        Assert.AreEqual("federation_resolve_endpoint", FederationMetadataParameterNames.ResolveEndpoint);
        Assert.AreEqual("federation_trust_mark_status_endpoint", FederationMetadataParameterNames.TrustMarkStatusEndpoint);
        Assert.AreEqual("federation_trust_mark_list_endpoint", FederationMetadataParameterNames.TrustMarkListEndpoint);
        Assert.AreEqual("federation_trust_mark_endpoint", FederationMetadataParameterNames.TrustMarkEndpoint);
        Assert.AreEqual("federation_historical_keys_endpoint", FederationMetadataParameterNames.HistoricalKeysEndpoint);
    }
}
