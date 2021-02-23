using DotDecentralized.Core;
using DotDecentralized.Core.Did;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;

namespace DotDecentralized.Tests
{
    /// <summary>
    /// General DID tests.
    /// </summary>
    public class DidDocumentTests
    {
        /// <summary>
        /// An example combining https://www.w3.org/TR/did-core/#example-19-various-service-endpoints and other pieces.
        /// </summary>
        private string MultiServiceTestDocument { get; } = @"{
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
        [Fact]
        public void EmptyDocumentHash()
        {
            _ = new DidDocument().GetHashCode();
        }


        /// <summary>
        /// Tests a complicated DID document.
        /// </summary>
        [Fact]
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
                    new VerificationRelationshipConverterFactory(),
                    new VerificationMethodConverter(),
                    new ServiceConverterFactory(serviceTypeMap.ToImmutableDictionary()),
                    new JsonLdContextConverter()
                }
            };

            DidDocument? deseserializedDidDocument = JsonSerializer.Deserialize<DidDocument>(MultiServiceTestDocument, options);
            string reserializedDidDocument = JsonSerializer.Serialize(deseserializedDidDocument, options);

            //All the DID documents need to have an ID and a context. This one needs to have also a strongly type element.
            //The strongly typed services should be in document order (e.g. not in type map order).
            Assert.NotNull(deseserializedDidDocument?.Id);
            Assert.NotNull(deseserializedDidDocument?.Context);
            Assert.NotNull(deseserializedDidDocument?.Service);
            Assert.NotNull(reserializedDidDocument);
            Assert.IsType<OpenIdConnectVersion1>(deseserializedDidDocument!.Service![0]);
            Assert.IsType<VerifiableCredentialService>(deseserializedDidDocument!.Service![5]);
            Assert.IsType<SocialWebInboxService>(deseserializedDidDocument!.Service![6]);
            Assert.IsType<Service>(deseserializedDidDocument!.Service![7]);

            var comparer = new JsonElementComparer();
            using var originalDIDDocument = JsonDocument.Parse(MultiServiceTestDocument);
            using var parsedReserializedDIDDocument = JsonDocument.Parse(reserializedDidDocument);
            Assert.True(comparer.Equals(originalDIDDocument.RootElement, parsedReserializedDIDDocument.RootElement), $"JSON string \"{MultiServiceTestDocument}\" did not pass roundtrip test.");
        }


        /// <summary>
        /// The reader should be able to deserialize all these test files correctly. These are files
        /// that are either from DID related specification examples or from real production systems.
        /// </summary>
        /// <param name="didDocumentFilename">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        /// <remarks>Compared to <see cref="CanRoundtripDidDocumentWithoutStronglyTypedService(string, string)"/>
        /// this tests provides strong type to see if <see cref="VerifiableCredentialService"/> in particular is serialized.</remarks>
        [Theory]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToCurrent + "Generic", "did-verifiablecredentialservice-1.json")]
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
                    new JsonLdContextConverter()
                }
            };

            DidDocument? deseserializedDidDocument = JsonSerializer.Deserialize<DidDocument>(didDocumentFileContents, options);
            string reserializedDidDocument = JsonSerializer.Serialize(deseserializedDidDocument, options);

            //All the DID documents need to have an ID and a context. This one needs to have also a strongly type element.
            Assert.NotNull(deseserializedDidDocument?.Id);
            Assert.NotNull(deseserializedDidDocument?.Context);
            Assert.NotNull(deseserializedDidDocument?.Service);
            Assert.NotNull(reserializedDidDocument);
            Assert.IsType<VerifiableCredentialService>(deseserializedDidDocument!.Service![0]);

            var comparer = new JsonElementComparer();
            using var originalDIDDocument = JsonDocument.Parse(didDocumentFileContents);
            using var parsedReserializedDIDDocument = JsonDocument.Parse(reserializedDidDocument);
            Assert.True(comparer.Equals(originalDIDDocument.RootElement, parsedReserializedDIDDocument.RootElement), $"File \"{didDocumentFilename}\" did not pass roundtrip test.");
        }


        /// <summary>
        /// The reader should be able to deserialize all these test files correctly.
        /// </summary>
        /// <param name="didDocumentFilename">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        /// <remarks>Compared to <see cref="CanRoundtripDidDocumentWithStronglyTypedService(string, string)"/>
        /// this tests without a provided strong type to see if <see cref="Service"/> is serialized.</remarks>
        [Theory]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToCurrent + "Generic", "did-verifiablecredentialservice-1.json")]
        public void CanRoundtripDidDocumentWithoutStronglyTypedService(string didDocumentFilename, string didDocumentFileContents)
        {
            TestInfrastructureConstants.ThrowIfPreconditionFails(didDocumentFilename, didDocumentFileContents);

            var serviceTypeMap = new Dictionary<string, Type>(ServiceConverterFactory.DefaultTypeMap);
            var options = new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly(new JsonNamingPolicy[] { JsonNamingPolicy.CamelCase })),
                Converters =
                {
                    new VerificationRelationshipConverterFactory(),
                    new VerificationMethodConverter(),
                    new ServiceConverterFactory(serviceTypeMap.ToImmutableDictionary()),
                    new JsonLdContextConverter()
                }
            };

            DidDocument? deseserializedDidDocument = JsonSerializer.Deserialize<DidDocument>(didDocumentFileContents, options);
            string reserializedDidDocument = JsonSerializer.Serialize(deseserializedDidDocument, options);

            //All the DID documents need to have an ID and a context. This one needs to have also a strongly typed Service,
            //VerifiableCredentialService, since no type was provided for it. The data is in Service ExtensionData element.
            Assert.NotNull(deseserializedDidDocument?.Id);
            Assert.NotNull(deseserializedDidDocument?.Context);
            Assert.NotNull(deseserializedDidDocument?.Service);
            Assert.NotNull(reserializedDidDocument);
            Assert.IsType<Service>(deseserializedDidDocument!.Service![0]);

            var comparer = new JsonElementComparer();
            using var originalDIDDocument = JsonDocument.Parse(didDocumentFileContents);
            using var parsedReserializedDIDDocument = JsonDocument.Parse(reserializedDidDocument);
            Assert.True(comparer.Equals(originalDIDDocument.RootElement, parsedReserializedDIDDocument.RootElement), $"File \"{didDocumentFilename}\" did not pass roundtrip test.");
        }


        /// <summary>
        /// Checks that the reader only can serialize and deserialize documents and does not
        /// read anything extra unless the DID document is extended to do so.
        /// </summary>
        /// <param name="didDocumentFilename">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        /// <remarks>By default reading is disallowed due to security and information leak concerns.</remarks>
        [Theory]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToExtended, "did-extended-1.json")]
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
                    new JsonLdContextConverter()
                }
            };

            DidDocument? deseserializedDidDocumentNonExtended = JsonSerializer.Deserialize<DidDocument>(didDocumentFileContents, options);
            TestExtendedDidDocument? deseserializedDidDocumentExtended = JsonSerializer.Deserialize<TestExtendedDidDocument>(didDocumentFileContents, options);
            string reserializedDidDocumentNonExtended = JsonSerializer.Serialize(deseserializedDidDocumentNonExtended, options);
            string reserializedDidDocumentExtended = JsonSerializer.Serialize(deseserializedDidDocumentExtended, options);

            //All the DID documents need to have an ID and a context. Here the extra data should not exist.
            Assert.NotNull(deseserializedDidDocumentNonExtended?.Id);
            Assert.NotNull(deseserializedDidDocumentNonExtended?.Context);
            Assert.NotNull(reserializedDidDocumentNonExtended);

            //Here there should be additional data.
            Assert.NotNull(deseserializedDidDocumentExtended?.Id);
            Assert.NotNull(deseserializedDidDocumentExtended?.Context);
            Assert.NotNull(deseserializedDidDocumentExtended?.AdditionalData);
            Assert.NotNull(reserializedDidDocumentExtended);

            var comparer = new JsonElementComparer();
            using var originalDIDDocument = JsonDocument.Parse(didDocumentFileContents);
            using var parsedReserializedDIDDocument = JsonDocument.Parse(reserializedDidDocumentExtended);
            Assert.True(comparer.Equals(originalDIDDocument.RootElement, parsedReserializedDIDDocument.RootElement), $"File \"{didDocumentFilename}\" did not pass roundtrip test.");
        }


        /// <summary>
        /// This checks plain <see cref="DidDocument"/> deserialization and serialization
        /// succeeds with any valid DID documents.
        /// </summary>
        /// <param name="didDocumentFilename">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        [Theory]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToCurrent, "*.json", SearchOption.AllDirectories)]
        public void AllTestDIDsAsPlainDocumentsRountrip(string didDocumentFilename, string didDocumentFileContents)
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
                    new JsonLdContextConverter()
                }
            };

            DidDocument? deseserializedDidDocument = JsonSerializer.Deserialize<DidDocument>(didDocumentFileContents, options);
            string reserializedDidDocument = JsonSerializer.Serialize(deseserializedDidDocument, options);

            //All the DID documents need to have an ID and a context.
            Assert.NotNull(deseserializedDidDocument?.Id);
            Assert.NotNull(deseserializedDidDocument?.Context);
            Assert.NotNull(reserializedDidDocument);

            var comparer = new JsonElementComparer();
            using var originalDIDDocument = JsonDocument.Parse(didDocumentFileContents);
            using var parsedReserializedDIDDocument = JsonDocument.Parse(reserializedDidDocument);
            Assert.True(comparer.Equals(originalDIDDocument.RootElement, parsedReserializedDIDDocument.RootElement), $"File \"{didDocumentFilename}\" did not pass roundtrip test.");
        }
    }
}
