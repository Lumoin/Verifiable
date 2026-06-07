using Verifiable.Core.SecurityEvents;
using Verifiable.Json;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Tests for <see cref="SsfDiscoveryJsonParsing.ParseTransmitterConfiguration"/> —
/// the faithful, strict parser for the Shared Signals Transmitter Configuration
/// Metadata document (SSF 1.0 §7.1). Strings stay strings; a malformed or
/// non-conformant document yields <see langword="null"/>.
/// </summary>
[TestClass]
internal sealed class SsfDiscoveryParsingTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void FullConfigurationParses()
    {
        const string Json = """
        {
            "spec_version": "1_0",
            "issuer": "https://transmitter.example/",
            "jwks_uri": "https://transmitter.example/jwks",
            "delivery_methods_supported": ["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"],
            "configuration_endpoint": "https://transmitter.example/ssf/streams",
            "status_endpoint": "https://transmitter.example/ssf/status",
            "add_subject_endpoint": "https://transmitter.example/ssf/subjects:add",
            "remove_subject_endpoint": "https://transmitter.example/ssf/subjects:remove",
            "verification_endpoint": "https://transmitter.example/ssf/verify",
            "critical_subject_members": ["user", "device"],
            "authorization_schemes": [{ "spec_urn": "urn:ietf:rfc:6749" }],
            "default_subjects": "NONE"
        }
        """;

        SsfTransmitterConfiguration? config = SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(Json);

        Assert.IsNotNull(config);
        Assert.AreEqual("https://transmitter.example/", config.Issuer);
        Assert.AreEqual("1_0", config.SpecVersion);
        Assert.AreEqual("https://transmitter.example/jwks", config.JwksUri);
        Assert.HasCount(2, config.DeliveryMethodsSupported!);
        Assert.IsTrue(SsfDeliveryMethods.IsPushHttp(config.DeliveryMethodsSupported![0]));
        Assert.IsTrue(SsfDeliveryMethods.IsPollHttp(config.DeliveryMethodsSupported[1]));
        Assert.AreEqual("https://transmitter.example/ssf/streams", config.ConfigurationEndpoint);
        Assert.AreEqual("https://transmitter.example/ssf/verify", config.VerificationEndpoint);
        Assert.HasCount(2, config.CriticalSubjectMembers!);
        Assert.HasCount(1, config.AuthorizationSchemes!);
        Assert.AreEqual("urn:ietf:rfc:6749", config.AuthorizationSchemes![0].SpecUrn);
        Assert.AreEqual(SsfMetadataParameterNames.DefaultSubjectsNone, config.DefaultSubjects);
    }


    [TestMethod]
    public void MinimalConfigurationWithOnlyIssuerParses()
    {
        SsfTransmitterConfiguration? config =
            SsfDiscoveryJsonParsing.ParseTransmitterConfiguration("""{ "issuer": "https://t.example/" }""");

        Assert.IsNotNull(config);
        Assert.AreEqual("https://t.example/", config.Issuer);
        Assert.IsNull(config.JwksUri);
        Assert.IsNull(config.DeliveryMethodsSupported);
        Assert.IsNull(config.AuthorizationSchemes);
        Assert.IsNull(config.DefaultSubjects);
    }


    [TestMethod]
    public void MissingIssuerIsRejected() =>
        Assert.IsNull(SsfDiscoveryJsonParsing.ParseTransmitterConfiguration("""{ "jwks_uri": "https://t.example/jwks" }"""));


    [TestMethod]
    public void NonObjectBodyIsRejected()
    {
        Assert.IsNull(SsfDiscoveryJsonParsing.ParseTransmitterConfiguration("[]"));
        Assert.IsNull(SsfDiscoveryJsonParsing.ParseTransmitterConfiguration("\"just a string\""));
        Assert.IsNull(SsfDiscoveryJsonParsing.ParseTransmitterConfiguration("not json"));
    }


    [TestMethod]
    public void WronglyTypedFieldIsRejected()
    {
        //issuer must be a string, not a number.
        Assert.IsNull(SsfDiscoveryJsonParsing.ParseTransmitterConfiguration("""{ "issuer": 42 }"""));
        //delivery_methods_supported must be an array of strings.
        Assert.IsNull(SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(
            """{ "issuer": "https://t.example/", "delivery_methods_supported": [1, 2] }"""));
    }


    [TestMethod]
    public void InvalidDefaultSubjectsValueIsRejected() =>
        Assert.IsNull(SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(
            """{ "issuer": "https://t.example/", "default_subjects": "SOME" }"""));


    [TestMethod]
    public void DefaultSubjectsAllParses()
    {
        SsfTransmitterConfiguration? config = SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(
            """{ "issuer": "https://t.example/", "default_subjects": "ALL" }""");

        Assert.IsNotNull(config);
        Assert.AreEqual(SsfMetadataParameterNames.DefaultSubjectsAll, config.DefaultSubjects);
    }


    [TestMethod]
    public void AuthorizationSchemeMissingSpecUrnIsRejected() =>
        Assert.IsNull(SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(
            """{ "issuer": "https://t.example/", "authorization_schemes": [{ "foo": "bar" }] }"""));
}
