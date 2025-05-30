using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Verifiable.Core;
using Verifiable.Core.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Core
{
    /// <summary>
    /// EBSI specific tests. The source is at <a href="https://api.ebsi.xyz/docs/?urls.primaryName=DID%20API#/DID/get-did-v1-identifier">EBSI DID API Swagger</a>.
    /// </summary>
    [TestClass]
    public sealed class EbsiDidTests
    {
        /// <summary>
        /// The reader should be able to deserialize all these test files correctly.
        /// </summary>
        /// <param name="didDocumentFilename">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        [TestMethod]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToDeprecated, "ebsi-did-1.json")]
        public void CanRoundtripLegacyEbsiDid(string didDocumentFilename, string didDocumentFileContents)
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
                    new DidIdConverter(did =>
                    {
                        return did switch
                        {
                            "did:ebsi:" => new EbsiDidMethod(did),
                            _ => new GenericDidMethod(did)
                        };
                    })
                }
            };

            TestExtendedDidDocument? deseserializedDidDocument = JsonSerializer.Deserialize<TestExtendedDidDocument>(didDocumentFileContents, options);
            string reserializedDidDocument = JsonSerializer.Serialize(deseserializedDidDocument, options);

            //All the DID documents need to have an ID and a context.
            Assert.IsNotNull(deseserializedDidDocument?.Id);
            Assert.IsNotNull(deseserializedDidDocument?.Context);
            Assert.IsFalse(string.IsNullOrWhiteSpace(reserializedDidDocument));

            //Currently EBSI DIDs have public key embedded in the main document.
            //This is not valid, but this is handled as "extra" that goes into
            //extension data element and can be handled from there. This checks
            //that this really is possible.
            //See further https://api.ebsi.xyz/docs/?urls.primaryName=DID%20API#/DID/get-did-v1-identifier
            //for the document description and how this is deprecated at https://www.w3.org/TR/did-spec-registries/#publickey
            //in favour of VerificationMethod.
            //
            //Also the contained key https://www.w3.org/TR/did-spec-registries/#ethereumaddress is deprecated in favour
            //of https://www.w3.org/TR/did-spec-registries/#blockchainaccountid.
            //
            //OBS! And test for testing extra registry types that are not part of the core specification
            //but that can nevertheless be part of core Nuget library.
            Assert.AreEqual(1, deseserializedDidDocument?.AdditionalData?.Count);
            Assert.IsInstanceOfType<JsonElement>(deseserializedDidDocument!.AdditionalData!["publicKey"]);
            
            var originalDIDDocument = JsonNode.Parse(didDocumentFileContents);
            var parsedReserializedDIDDocument = JsonNode.Parse(reserializedDidDocument);            
            Assert.IsTrue(JsonNode.DeepEquals(originalDIDDocument, parsedReserializedDIDDocument), $"File \"{didDocumentFilename}\" did not pass roundtrip test.");
        }
    }
}
