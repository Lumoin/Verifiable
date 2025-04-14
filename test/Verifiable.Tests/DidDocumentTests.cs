using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core;
using Verifiable.Core.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Jwt;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Core
{
    /// <summary>
    /// General DID tests.
    /// </summary>
    [TestClass]
    public sealed class DidDocumentTests
    {
        /// <summary>
        /// An example combining https://www.w3.org/TR/did-core/#example-19-various-service-endpoints and other pieces.
        /// </summary>
        private string MultiServiceTestDocument { get; } = /*lang=json,strict*/ @"{
            ""@context"": ""https://www.w3.org/ns/did/v1"",
              ""id"": ""did:example:123456789abcdefghi"",
              ""verificationMethod"": [{
                ""id"": ""did:example:123456789abcdefghi#keys-1"",
                ""type"": ""RsaVerificationKey2018"",
                ""controller"": ""did:example:123456789abcdefghi"",
                ""publicKeyPem"": ""-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n""
              }, {
                ""id"": ""did:example:123456789abcdefghi#keys-3"",
                ""type"": ""RsaVerificationKey2018"",
                ""controller"": ""did:example:123456789abcdefghi"",
                ""publicKeyPem"": ""-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n""
               }, {
                  ""id"": ""did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"",
                  ""type"": ""JwsVerificationKey2020"",
                  ""controller"": ""did:example:123"",
                  ""publicKeyJwk"": {
                  ""crv"": ""Ed25519"",
                  ""x"": ""VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"",
                  ""kty"": ""OKP"",
                  ""kid"": ""_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A""
                }
              }],
              ""authentication"": [
                ""did:example:123456789abcdefghi#keys-1"",
                ""did:example:123456789abcdefghi#keys-3"",
                {
                  ""id"": ""did:example:123456789abcdefghi#keys-2"",
                  ""type"": ""Ed25519VerificationKey2018"",
                  ""controller"": ""did:example:123456789abcdefghi"",
                  ""publicKeyBase58"": ""H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV""
                }
              ],
              ""service"": [{
                ""id"": ""did:example:123456789abcdefghi#openid"",
                ""type"": ""OpenIdConnectVersion1.0Service"",
                ""serviceEndpoint"": ""https://openid.example.com/""
                }, {
                ""id"": ""did:example:123456789abcdefghi#vcr"",
                ""type"": ""CredentialRepositoryService"",
                ""serviceEndpoint"": ""https://repository.example.com/service/8377464""
                }, {
                ""id"": ""did:example:123456789abcdefghi#xdi"",
                ""type"": ""XdiService"",
                ""serviceEndpoint"": ""https://xdi.example.com/8377464""
                }, {
                ""id"": ""did:example:123456789abcdefghi#agent"",
                ""type"": ""AgentService"",
                ""serviceEndpoint"": ""https://agent.example.com/8377464""
                }, {
                ""id"": ""did:example:123456789abcdefghi#messages"",
                ""type"": ""MessagingService"",
                ""serviceEndpoint"": ""https://example.com/messages/8377464""
                }, {
                ""id"": ""did:example:123456789abcdefghi#vcs"",
                ""type"": ""VerifiableCredentialService"",
                ""serviceEndpoint"": ""https://example.com/vc/""
                }, {
                ""id"": ""did:example:123456789abcdefghi#inbox"",
                ""type"": ""SocialWebInboxService"",
                ""serviceEndpoint"": ""https://social.example.com/83hfh37dj"",
                ""description"": ""My public social inbox"",
                ""spamCost"": {
                    ""amount"": ""0.50"",
                    ""currency"": ""USD""
                }}, {
                ""id"": ""did:example:123456789abcdefghi#authpush"",
                ""type"": ""DidAuthPushModeVersion1"",
                ""serviceEndpoint"": ""http://auth.example.com/did:example:123456789abcdefg""
              }]
            }";


        /// <summary>
        /// Getting a hash of an empty document. This should not throw.
        /// </summary>
        [TestMethod]
        public void EmptyDocumentHash()
        {
            _ = new DidDocument().GetHashCode();
        }


        /// <summary>
        /// Tests a complicated DID document.
        /// </summary>
        [TestMethod]
        public void FullDidDocumentTest()
        {
            var serviceTypeMap = new Dictionary<string, Type>(ServiceConverterFactory.DefaultTypeMap)
            {
                { "OpenIdConnectVersion1.0Service", typeof(OpenIdConnectVersion1) },
                { "CredentialRepositoryService", typeof(Service) },
                { "XdiService", typeof(Service) },
                { "AgentService", typeof(Service) },
                { "IdentityHub", typeof(Service) },
                { "MessagingService", typeof(Service) },
                { "SocialWebInboxService", typeof(SocialWebInboxService) },
                { "VerifiableCredentialService", typeof(VerifiableCredentialService) },
                { "DidAuthPushModeVersion1", typeof(Service) }
            };

            var options = new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly(new JsonNamingPolicy[] { JsonNamingPolicy.CamelCase })),
                PropertyNameCaseInsensitive = true,
                Converters =
                {
                    new SingleOrArrayControllerConverter(),
                    new SingleOrArrayVerificationMethodConverter(),
                    new VerificationRelationshipConverterFactory(),
                    new VerificationMethodConverter(),
                    new ServiceConverterFactory(serviceTypeMap.ToImmutableDictionary()),
                    new JsonLdContextConverter(),
                    new DictionaryStringObjectJsonConverter(),
                    new DidIdConverter(did =>
                    {
                        return did switch
                        {
                            "did:key:" => new KeyDidMethod(did),
                            "did:ebsi:" => new EbsiDidMethod(did),
                            _ => new GenericDidMethod(did)
                        };
                    })
                }
            };

            var (deserializedDidDocument, reserializedDidDocument) = JsonTestingUtilities.PerformSerializationCycle<DidDocument>(MultiServiceTestDocument, options);
            Assert.IsNotNull(deserializedDidDocument?.Id);
            Assert.IsNotNull(deserializedDidDocument?.Context);
            Assert.IsNotNull(deserializedDidDocument?.Service);
            Assert.IsNotNull(reserializedDidDocument);
            Assert.IsInstanceOfType<OpenIdConnectVersion1>(deserializedDidDocument!.Service![0]);
            Assert.IsInstanceOfType<VerifiableCredentialService>(deserializedDidDocument!.Service![5]);
            Assert.IsInstanceOfType<SocialWebInboxService>(deserializedDidDocument!.Service![6]);
            Assert.IsInstanceOfType<Service>(deserializedDidDocument!.Service![7]);

            bool areJsonElementsEqual = JsonTestingUtilities.CompareJsonElements(MultiServiceTestDocument, reserializedDidDocument);
            Assert.IsTrue(areJsonElementsEqual, $"JSON string \"{MultiServiceTestDocument}\" did not pass roundtrip test.");
        }


        /// <summary>
        /// The reader should be able to deserialize all these test files correctly. These are files
        /// that are either from DID related specification examples or from real production systems.
        /// </summary>
        /// <param name="didDocumentFilename">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        /// <remarks>Compared to <see cref="CanRoundtripDidDocumentWithoutStronglyTypedService(string, string)"/>
        /// this tests provides strong type to see if <see cref="VerifiableCredentialService"/> in particular is serialized.</remarks>
        [TestMethod]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToCurrent, "did-verifiablecredentialservice-1.json")]
        public void CanRoundtripDidDocumentWithStronglyTypedService(string didDocumentFilename, string didDocumentFileContents)
        {
            TestInfrastructureConstants.ThrowIfPreconditionFails(didDocumentFilename, didDocumentFileContents);

            var serviceTypeMap = new Dictionary<string, Type>(ServiceConverterFactory.DefaultTypeMap)
            {
                { "VerifiableCredentialService", typeof(VerifiableCredentialService) }
            };

            var options = new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly(new JsonNamingPolicy[] { JsonNamingPolicy.CamelCase })),
                Converters =
                {
                    new VerificationRelationshipConverterFactory(),
                    new VerificationMethodConverter(),
                    new ServiceConverterFactory(serviceTypeMap.ToImmutableDictionary()),
                    new JsonLdContextConverter(),
                    new DictionaryStringObjectJsonConverter(),
                    new DidIdConverter(did =>
                    {
                        return did switch
                        {
                            "did:key:" => new KeyDidMethod(did),
                            "did:ebsi:" => new EbsiDidMethod(did),
                            _ => new GenericDidMethod(did)
                        };
                    })
                }
            };

            var (deserializedDidDocument, reserializedDidDocument) = JsonTestingUtilities.PerformSerializationCycle<DidDocument>(didDocumentFileContents, options);
            Assert.IsNotNull(deserializedDidDocument?.Id);
            Assert.IsNotNull(deserializedDidDocument?.Context);
            Assert.IsNotNull(deserializedDidDocument?.Service);
            Assert.IsNotNull(reserializedDidDocument);
            Assert.IsInstanceOfType<VerifiableCredentialService>(deserializedDidDocument!.Service![0]);

            bool areJsonElementsEqual = JsonTestingUtilities.CompareJsonElements(didDocumentFileContents, reserializedDidDocument);
            Assert.IsTrue(areJsonElementsEqual, $"File \"{didDocumentFilename}\" did not pass roundtrip test.");
        }


        /// <summary>
        /// The reader should be able to deserialize all these test files correctly.
        /// </summary>
        /// <param name="didDocumentFilename">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        /// <remarks>Compared to <see cref="CanRoundtripDidDocumentWithStronglyTypedService(string, string)"/>
        /// this tests without a provided strong type to see if <see cref="Service"/> is serialized.</remarks>
        [TestMethod]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToCurrent, "did-verifiablecredentialservice-1.json")]
        public void CanRoundtripDidDocumentWithoutStronglyTypedService(string didDocumentFilename, string didDocumentFileContents)
        {
            TestInfrastructureConstants.ThrowIfPreconditionFails(didDocumentFilename, didDocumentFileContents);

            var verificationMethodTypeMap = new Dictionary<string, Func<string, JsonSerializerOptions, KeyFormat>>(VerificationMethodConverter.DefaultTypeMap)
            {
                { "JsonWebKey2020", new Func<string, JsonSerializerOptions, PublicKeyJwk>((json, options) => JsonSerializer.Deserialize<PublicKeyJwk>(json, options)!) }
            };

            var options = new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly(new JsonNamingPolicy[] { JsonNamingPolicy.CamelCase })),
                Converters =
                {
                    new VerificationRelationshipConverterFactory(),
                    new VerificationMethodConverter(cryptoSuite =>
                    {
                        return cryptoSuite switch
                        {
                            "JsonWebKey2020" => new JsonWebKey2020(),
                            "Ed25519VerificationKey2020" => new Ed25519VerificationKey2020(),
                            _ => new CryptoSuite(cryptoSuite, new List<string>())
                        };
                    },verificationMethodTypeMap.ToImmutableDictionary()),
                    new ServiceConverterFactory(),
                    new JsonLdContextConverter(),
                    new DidIdConverter(did =>
                    {
                        return did switch
                        {
                            "did:key:" => new KeyDidMethod(did),
                            "did:ebsi:" => new EbsiDidMethod(did),
                            _ => new GenericDidMethod(did)
                        };
                    })
                }
            };

            var (deserializedDidDocument, reserializedDidDocument) = JsonTestingUtilities.PerformSerializationCycle<DidDocument>(didDocumentFileContents, options);
            Assert.IsNotNull(deserializedDidDocument?.Id);
            Assert.IsNotNull(deserializedDidDocument?.Context);
            Assert.IsNotNull(deserializedDidDocument?.Service);
            Assert.IsNotNull(reserializedDidDocument);
            Assert.IsInstanceOfType<Service>(deserializedDidDocument!.Service![0]);

            bool areJsonElementsEqual = JsonTestingUtilities.CompareJsonElements(didDocumentFileContents, reserializedDidDocument);
            Assert.IsTrue(areJsonElementsEqual, $"File \"{didDocumentFilename}\" did not pass roundtrip test.");
        }


        /// <summary>
        /// Checks that the reader only can serialize and deserialize documents and does not
        /// read anything extra unless the DID document is extended to do so.
        /// </summary>
        /// <param name="didDocumentFilename">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        /// <remarks>By default reading is disallowed due to security and information leak concerns.</remarks>
        [TestMethod]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToExtended, "did-w3c-extended-1.json")]
        public void CanRoundtripExtendedDidOnlyWithExtendedType(string didDocumentFilename, string didDocumentFileContents)
        {
            TestInfrastructureConstants.ThrowIfPreconditionFails(didDocumentFilename, didDocumentFileContents);

            var options = new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly(new JsonNamingPolicy[] { JsonNamingPolicy.CamelCase })),
                Converters =
                {
                    new VerificationRelationshipConverterFactory(),
                    new VerificationMethodConverter(),
                    new ServiceConverterFactory(),
                    new JsonLdContextConverter(),
                    new DictionaryStringObjectJsonConverter(),
                    new DidIdConverter(did =>
                    {
                        return did switch
                        {
                            "did:key:" => new KeyDidMethod(did),
                            "did:ebsi:" => new EbsiDidMethod(did),
                            _ => new GenericDidMethod(did)
                        };
                    })
                }
            };

            var (deserializedDidDocumentNonExtended, deserializedDidDocumentExtended, reserializedDidDocumentNonExtended, reserializedDidDocumentExtended) =
                JsonTestingUtilities.PerformExtendedSerializationCycle<DidDocument, TestExtendedDidDocument>(didDocumentFileContents, options);

            //Assertions for DidDocument...
            Assert.IsNotNull(deserializedDidDocumentNonExtended?.Id);
            Assert.IsNotNull(deserializedDidDocumentNonExtended?.Context);
            Assert.IsNotNull(reserializedDidDocumentNonExtended);

            //Assertions for TestExtendedDidDocument...
            Assert.IsNotNull(deserializedDidDocumentExtended?.Id);
            Assert.IsNotNull(deserializedDidDocumentExtended?.Context);
            Assert.IsNotNull(deserializedDidDocumentExtended?.AdditionalData);
            Assert.IsNotNull(reserializedDidDocumentExtended);

            bool areJsonElementsEqual = JsonTestingUtilities.CompareJsonElements(didDocumentFileContents, reserializedDidDocumentExtended);
            Assert.IsTrue(areJsonElementsEqual, $"File \"{didDocumentFilename}\" did not pass roundtrip test.");
        }


        /// <summary>
        /// This checks plain <see cref="DidDocument"/> deserialization and serialization
        /// succeeds with any valid DID documents.
        /// </summary>
        /// <param name="didDocumentFilename">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        [TestMethod]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToCurrent, ".json", SearchOption.AllDirectories)]
        public void AllTestDIDsAsPlainDocumentsRountrip(string didDocumentFilename, string didDocumentFileContents)
        {
            TestInfrastructureConstants.ThrowIfPreconditionFails(didDocumentFilename, didDocumentFileContents);

            var verificationMethodTypeMap = new Dictionary<string, Func<string, JsonSerializerOptions, KeyFormat>>(VerificationMethodConverter.DefaultTypeMap)
            {
                { "JsonWebKey2020", new Func<string, JsonSerializerOptions, PublicKeyJwk>((json, options) => JsonSerializer.Deserialize<PublicKeyJwk>(json, options)!) }
            };

            var options = new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly(new JsonNamingPolicy[] { JsonNamingPolicy.CamelCase })),
                Converters =
                {
                    new SingleOrArrayControllerConverter(),
                    new VerificationRelationshipConverterFactory(),
                    new VerificationMethodConverter(cryptoSuite =>
                    {
                        return cryptoSuite switch
                        {
                            "JsonWebKey2020" => new JsonWebKey2020(),
                            "Ed25519VerificationKey2020" => new Ed25519VerificationKey2020(),
                            _ => new CryptoSuite(cryptoSuite, new List<string>())
                        };
                    },verificationMethodTypeMap.ToImmutableDictionary()),
                    new ServiceConverterFactory(),
                    new JsonLdContextConverter(),
                    new DictionaryStringObjectJsonConverter(),
                    new DidIdConverter(did =>
                    {
                        return did switch
                        {
                            "did:key:" => new KeyDidMethod(did),
                            "did:ebsi:" => new EbsiDidMethod(did),
                            _ => new GenericDidMethod(did)
                        };
                    })
                }
            };

            var (deserializedDidDocument, reserializedDidDocument) = JsonTestingUtilities.PerformSerializationCycle<DidDocument>(didDocumentFileContents, options);

            //All the DID documents need to have an ID.
            Assert.IsNotNull(deserializedDidDocument?.Id);
            Assert.IsNotNull(reserializedDidDocument);

            bool areJsonElementsEqual = JsonTestingUtilities.CompareJsonElements(didDocumentFileContents, reserializedDidDocument);
            Assert.IsTrue(areJsonElementsEqual, $"File \"{didDocumentFilename}\" did not pass roundtrip test.");
        }
    }
}
