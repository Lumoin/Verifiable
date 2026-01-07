using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Verifiable.Json.Converters;
using Verifiable.Sidetree;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Did
{
    /// <summary>
    /// Sidetree specific tests. See https://identity.foundation/ion/explorer/ for documents.
    /// </summary>
    [TestClass]
    public sealed class SidetreeTests
    {
        /// <summary>
        /// The reader should be able to deserialize all these test files correctly.
        /// </summary>
        /// <param name="didDocumentFileName">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        [TestMethod]
        [Ignore("Needs a change in DidCore.Service implementation. See comments there.")]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToSidetree, "ion-1.json")]
        public void CanRoundtripIonDid(string didDocumentFilename, string didDocumentFileContents)
        {
            TestInfrastructureConstants.ThrowIfPreconditionFails(didDocumentFilename, didDocumentFileContents);

            var options = new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly([JsonNamingPolicy.CamelCase])),
                Converters =
                {
                    new VerificationMethodReferenceConverterFactory(),
                    new VerificationMethodConverter(),
                    new ServiceConverterFactory(),
                    new JsonLdContextConverter()
                }
            };

            SideTreeDocument? deseserializedDidDocument = JsonSerializer.Deserialize<SideTreeDocument>(didDocumentFileContents, options);
            string reserializedDidDocument = JsonSerializer.Serialize(deseserializedDidDocument, options);

            //All the DID documents need to have an ID and a context.
            Assert.IsNotNull(deseserializedDidDocument?.Context);
            Assert.IsNotNull(deseserializedDidDocument?.DidDocument);
            Assert.IsFalse(string.IsNullOrWhiteSpace(reserializedDidDocument));
            
            var originalDIDDocument = JsonNode.Parse(didDocumentFileContents);
            var parsedReserializedDIDDocument = JsonNode.Parse(reserializedDidDocument);
            Assert.IsTrue(JsonNode.DeepEquals(originalDIDDocument, parsedReserializedDIDDocument), $"File \"{didDocumentFilename}\" did not pass roundtrip test.");
        }
    }
}
