using DotDecentralized.Core;
using DotDecentralized.Core.Did;
using DotDecentralized.Sidetree;
using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;

namespace DotDecentralized.Tests
{
    /// <summary>
    /// Sidetree specific tests. See https://identity.foundation/ion/explorer/ for documents.
    /// </summary>
    public class SidetreeTests
    {
        /// <summary>
        /// The reader should be able to deserialize all these test files correctly.
        /// </summary>
        /// <param name="didDocumentFileName">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        [Theory(Skip = "Needs a change in DidCore.Servic implementation. See comments there.")]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToSidetree, "ion-1.json")]
        public void CanRoundtripIonDid(string didDocumentFilename, string didDocumentFileContents)
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

            SideTreeDocument? deseserializedDidDocument = JsonSerializer.Deserialize<SideTreeDocument>(didDocumentFileContents, options);
            string reserializedDidDocument = JsonSerializer.Serialize(deseserializedDidDocument, options);

            //All the DID documents need to have an ID and a context.
            Assert.NotNull(deseserializedDidDocument?.Context);
            Assert.NotNull(deseserializedDidDocument?.DidDocument);
            Assert.NotNull(reserializedDidDocument);

            var comparer = new JsonElementComparer();
            using var originalDIDDocument = JsonDocument.Parse(didDocumentFileContents);
            using var parsedReserializedDIDDocument = JsonDocument.Parse(reserializedDidDocument);
            Assert.True(comparer.Equals(originalDIDDocument.RootElement, parsedReserializedDIDDocument.RootElement), $"File \"{didDocumentFilename}\" did not pass roundtrip test.");
        }
    }
}
