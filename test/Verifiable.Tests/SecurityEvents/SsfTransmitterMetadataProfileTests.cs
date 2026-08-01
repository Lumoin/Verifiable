using System;
using System.Collections.Generic;
using Verifiable.Core.SecurityEvents;
using Verifiable.Json;
using Verifiable.OAuth.Ssf;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Tests that the Transmitter Configuration Metadata emission never produces a
/// document that violates the CAEP Interoperability Profile 1.0 §2.3 metadata
/// requirements: <c>delivery_methods_supported</c> (§2.3.2) and
/// <c>authorization_schemes</c> (§2.3.7) are MUST-include there, where the base
/// Shared Signals Framework 1.0 §7.1 leaves them RECOMMENDED and OPTIONAL.
/// </summary>
/// <remarks>
/// <see href="https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html">OpenID
/// CAEP Interoperability Profile 1.0, draft 01</see> — no Final text exists; draft 01 is the
/// document under public review.
/// <para>
/// The emitted bytes are consumed by the RECEIVER's strict parser, never by a
/// hand-rolled assertion over the JSON text, so these tests exercise the same
/// wire contract a real Receiver sees.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SsfTransmitterMetadataProfileTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The Transmitter Issuer Identifier the emitted documents carry.</summary>
    private static Uri Issuer { get; } = new("https://transmitter.example/");


    /// <summary>
    /// A deployment that declares no delivery methods cannot produce a §2.3.2-conformant
    /// document, so the emit path MUST refuse with a diagnostic naming the missing member
    /// rather than silently publishing a document without it.
    /// </summary>
    [TestMethod]
    public void UnsetDeliveryMethodsRefusesInsteadOfEmittingAViolatingDocument()
    {
        ArgumentException refusal = Assert.Throws<ArgumentException>(
            () => SsfTransmitterJsonWriting.BuildTransmitterConfigurationJson(
                Issuer, EndpointMembers(), SsfTransmitterMetadataContribution.Empty));

        Assert.Contains(
            SsfMetadataParameterNames.DeliveryMethodsSupported,
            refusal.Message,
            StringComparison.Ordinal,
            "The refusal diagnostic must name the metadata member the deployment failed to supply.");
    }


    /// <summary>
    /// §2.3.7 fixes the value: the document MUST include <c>authorization_schemes</c> and that
    /// value MUST include <c>{"spec_urn": "urn:ietf:rfc:6749"}</c>. The value is spec-defined,
    /// so a contribution that leaves it unset gets the spec-defined value, not an omission.
    /// </summary>
    [TestMethod]
    public void UnsetAuthorizationSchemesEmitsTheProfileFixedValue()
    {
        string json = SsfTransmitterJsonWriting.BuildTransmitterConfigurationJson(
            Issuer,
            EndpointMembers(),
            new SsfTransmitterMetadataContribution
            {
                DeliveryMethodsSupported = [SsfDeliveryMethods.PushHttp, SsfDeliveryMethods.PollHttp]
            });

        SsfTransmitterConfiguration? parsed = SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(json);

        Assert.IsNotNull(parsed, $"The emitted metadata must strict-parse. Json: {json}");
        Assert.IsNotNull(
            parsed.AuthorizationSchemes,
            $"Profile §2.3.7 makes authorization_schemes MUST-include. Json: {json}");
        Assert.ContainsSingle(parsed.AuthorizationSchemes!);
        Assert.AreEqual(
            SsfMetadataParameterNames.AuthorizationSchemeSpecUrnOAuth2,
            parsed.AuthorizationSchemes![0].SpecUrn);
    }


    /// <summary>
    /// A deployment that declares its own authorization schemes keeps them verbatim — the
    /// spec-defined value is a default for silence, never a rewrite of declared policy.
    /// </summary>
    [TestMethod]
    public void SuppliedAuthorizationSchemesAreEmittedVerbatim()
    {
        string json = SsfTransmitterJsonWriting.BuildTransmitterConfigurationJson(
            Issuer,
            EndpointMembers(),
            new SsfTransmitterMetadataContribution
            {
                DeliveryMethodsSupported = [SsfDeliveryMethods.PollHttp],
                AuthorizationSchemeSpecUrns = ["urn:example:scheme"]
            });

        SsfTransmitterConfiguration? parsed = SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(json);

        Assert.IsNotNull(parsed, $"The emitted metadata must strict-parse. Json: {json}");
        Assert.ContainsSingle(parsed.AuthorizationSchemes!);
        Assert.AreEqual("urn:example:scheme", parsed.AuthorizationSchemes![0].SpecUrn);
    }


    /// <summary>
    /// The chain-derived endpoint members every emitted document carries; only
    /// <c>jwks_uri</c> is needed for these assertions.
    /// </summary>
    private static IReadOnlyList<KeyValuePair<string, string>> EndpointMembers() =>
        [new KeyValuePair<string, string>(SsfMetadataParameterNames.JwksUri, "https://transmitter.example/jwks")];
}
