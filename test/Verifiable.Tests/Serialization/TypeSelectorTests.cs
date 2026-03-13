using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Verifiable.Core.Model.Did;
using Verifiable.Json;
using Verifiable.Json.Converters;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

[JsonSerializable(typeof(Service))]
[JsonSerializable(typeof(Service[]))]
[JsonSerializable(typeof(TypeSelectorTests.TestIdentityResolverService))]
[JsonSerializable(typeof(TypeSelectorTests.TestBlockchainVerificationMethod))]
internal partial class TypeSelectorTestsJsonContext: JsonSerializerContext { }

/// <summary>
/// Tests for the unified type selector pattern across <see cref="ServiceConverter"/>,
/// <see cref="VerificationMethodConverter"/>, and <see cref="DataIntegrityProofConverter"/>.
/// </summary>
[TestClass]
internal sealed class TypeSelectorTests
{
    /// <summary>
    /// A test service subclass representing a UNTP Identity Resolver service.
    /// Downstream libraries would define this; here it proves the extensibility mechanism.
    /// </summary>
    internal class TestIdentityResolverService: Service
    {
        /// <summary>
        /// The supported link types for this identity resolver.
        /// </summary>
        public string? SupportedLinkType { get; set; }
    }

    /// <summary>
    /// A test verification method subclass carrying a blockchain account identifier.
    /// Proves that CID 1.1 "MAY include additional properties" works through the
    /// converter pipeline.
    /// </summary>
    internal class TestBlockchainVerificationMethod: VerificationMethod
    {
        /// <summary>
        /// The blockchain account identifier per CAIP-10.
        /// </summary>
        public string? BlockchainAccountId { get; set; }
    }

    private static JsonSerializerOptions CreateOptions(ServiceTypeSelector? serviceSelector = null)
    {
        //Insert custom ServiceConverter before ApplyVerifiableDefaults adds the default one.
        var customServiceConverter = new ServiceConverter(serviceSelector ?? ServiceTypeSelectors.Default);
        var options = new JsonSerializerOptions();
        options.Converters.Insert(0, customServiceConverter);
        options.ApplyVerifiableDefaults();
        //Combine so ServiceConverter.GetTypeInfo can resolve both library and test-internal types.
        options.TypeInfoResolver = JsonTypeInfoResolver.Combine(
            VerifiableJsonContext.Default,
            TypeSelectorTestsJsonContext.Default);
        return options;
    }


    private static ServiceTypeSelector CreateIdentityResolverSelector()
    {
        var defaultSelector = ServiceTypeSelectors.Default;
        return serviceType => serviceType switch
        {
            "IdentityResolverService" => typeof(TestIdentityResolverService),
            _ => defaultSelector(serviceType)
        };
    }


    [TestMethod]
    public void DefaultServiceTypeSelectorReturnsBaseServiceType()
    {
        Type result = ServiceTypeSelectors.Default("SomeUnknownService");

        Assert.AreEqual(typeof(Service), result);
    }

    [TestMethod]
    public void DefaultVerificationMethodTypeSelectorReturnsBaseType()
    {
        Type result = VerificationMethodTypeSelectors.Default("JsonWebKey2020");

        Assert.AreEqual(typeof(VerificationMethod), result);
    }

    [TestMethod]
    public void DefaultVerificationMethodTypeSelectorReturnsBaseTypeForUnknown()
    {
        Type result = VerificationMethodTypeSelectors.Default("SomeCustomMethod2025");

        Assert.AreEqual(typeof(VerificationMethod), result);
    }

    [TestMethod]
    public void CustomServiceTypeSelectorChainsToDefault()
    {
        var custom = CreateIdentityResolverSelector();

        Assert.AreEqual(typeof(TestIdentityResolverService), custom("IdentityResolverService"));
        Assert.AreEqual(typeof(Service), custom("SomeOtherService"));
    }

    [TestMethod]
    public void CustomVerificationMethodTypeSelectorChainsToDefault()
    {
        var defaultSelector = VerificationMethodTypeSelectors.Default;
        VerificationMethodTypeSelector custom = vmType => vmType switch
        {
            "EcdsaSecp256k1RecoveryMethod2020" => typeof(TestBlockchainVerificationMethod),
            _ => defaultSelector(vmType)
        };

        Assert.AreEqual(typeof(TestBlockchainVerificationMethod), custom("EcdsaSecp256k1RecoveryMethod2020"));
        Assert.AreEqual(typeof(VerificationMethod), custom("Multikey"));
        Assert.AreEqual(typeof(VerificationMethod), custom("UnknownType"));
    }

    [TestMethod]
    public void ServiceConverterUsesCustomSelector()
    {
        var options = CreateOptions(CreateIdentityResolverSelector());

        string json = /*lang=json,strict*/ """
            {
                "id": "did:example:123#idr",
                "type": "IdentityResolverService",
                "serviceEndpoint": "https://resolver.example.com",
                "supportedLinkType": "gs1:linkType:certificationInfo"
            }
            """;

        var service = JsonSerializerExtensions.Deserialize<Service>(json, options);

        Assert.IsNotNull(service);
        Assert.IsInstanceOfType<TestIdentityResolverService>(service);

        var idr = (TestIdentityResolverService)service;
        Assert.AreEqual("gs1:linkType:certificationInfo", idr.SupportedLinkType);
        Assert.AreEqual("IdentityResolverService", idr.Type);
    }

    [TestMethod]
    public void ServiceConverterRoundTripsCustomSubclass()
    {
        var options = CreateOptions(CreateIdentityResolverSelector());

        string json = /*lang=json,strict*/ """
            {
                "id": "did:example:123#idr",
                "type": "IdentityResolverService",
                "serviceEndpoint": "https://resolver.example.com",
                "supportedLinkType": "gs1:linkType:certificationInfo"
            }
            """;

        var deserialized = JsonSerializerExtensions.Deserialize<Service>(json, options);
        var reserialized = JsonSerializerExtensions.Serialize(deserialized, options);

        //Verify the custom property survived round-trip.
        using var doc = JsonDocument.Parse(reserialized);
        Assert.IsTrue(doc.RootElement.TryGetProperty("supportedLinkType", out var linkTypeElement));
        Assert.AreEqual("gs1:linkType:certificationInfo", linkTypeElement.GetString());
    }

    [TestMethod]
    public void ServiceConverterFallsBackToBaseForUnknownTypes()
    {
        var options = CreateOptions();

        string json = /*lang=json,strict*/ """
            {
                "id": "did:example:123#messages",
                "type": "MessagingService",
                "serviceEndpoint": "https://messages.example.com"
            }
            """;

        var service = JsonSerializerExtensions.Deserialize<Service>(json, options);

        Assert.IsNotNull(service);
        Assert.AreEqual(typeof(Service), service.GetType());
        Assert.AreEqual("MessagingService", service.Type);
    }

    [TestMethod]
    public void SharedVerificationMethodTypeSelectorAcrossConverters()
    {
        //Both VerificationMethodConverter and DataIntegrityProofConverter
        //should use the same selector instance.
        var defaultSelector = VerificationMethodTypeSelectors.Default;
        VerificationMethodTypeSelector sharedSelector = vmType => vmType switch
        {
            "EcdsaSecp256k1RecoveryMethod2020" => typeof(TestBlockchainVerificationMethod),
            _ => defaultSelector(vmType)
        };

        //The same selector produces the same type regardless of which converter calls it.
        Type fromDid = sharedSelector("EcdsaSecp256k1RecoveryMethod2020");
        Type fromProof = sharedSelector("EcdsaSecp256k1RecoveryMethod2020");
        Type standardType = sharedSelector("Multikey");

        Assert.AreEqual(fromDid, fromProof);
        Assert.AreEqual(typeof(TestBlockchainVerificationMethod), fromDid);
        Assert.AreEqual(typeof(VerificationMethod), standardType);
    }

    [TestMethod]
    public void ServiceConverterHandlesMultipleServicesInDocument()
    {
        var options = CreateOptions(CreateIdentityResolverSelector());

        string json = /*lang=json,strict*/ """
            [
                {
                    "id": "did:example:123#idr",
                    "type": "IdentityResolverService",
                    "serviceEndpoint": "https://resolver.example.com",
                    "supportedLinkType": "gs1:linkType:certificationInfo"
                },
                {
                    "id": "did:example:123#messages",
                    "type": "MessagingService",
                    "serviceEndpoint": "https://messages.example.com"
                }
            ]
            """;

        var services = JsonSerializerExtensions.Deserialize<Service[]>(json, options);

        Assert.IsNotNull(services);
        Assert.HasCount(2, services);
        Assert.IsInstanceOfType<TestIdentityResolverService>(services[0]);
        Assert.IsInstanceOfType<Service>(services[1]);
        Assert.AreEqual(typeof(Service), services[1].GetType());
    }
}