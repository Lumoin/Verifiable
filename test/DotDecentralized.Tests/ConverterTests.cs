using DotDecentralized.Core.Did;
using System.Text.Json;
using Xunit;

namespace DotDecentralized.Tests
{
    //TODO: Add more tests that check both positive and negative results: what should pass and not pass with
    //known specification conformant and non-conformant fragments, with strong types, no types and with
    //extension and not extensions (a common case probably is user having extended some elements) and
    //potentially legacy and so on.

    /// <summary>
    /// Tests for individual converters.
    /// </summary>
    public class ConverterTests
    {
        /// <summary>
        /// A sample test service copied from https://www.w3.org/TR/did-core/.
        /// </summary>
        private string TestService1 => @"{
                ""id"": ""did:example:123456789abcdefghi#oidc"",
                ""type"": ""OpenIdConnectVersion1.0Service"",
                ""serviceEndpoint"": ""https://openid.example.com/"" }";

        /// <summary>
        /// The DID Uri from https://www.w3.org/TR/did-core/.
        /// </summary>
        private string OneUriContext => @"{""@context"": ""https://www.w3.org/ns/did/v1""}";

        /// <summary>
        /// A collection of URIs in context.
        /// </summary>
        private string CollectionUriContext => @"{""@context"": [""https://w3id.org/future-method/v1"", ""https://w3id.org/veres-one/v1""]}";

        /// <summary>
        /// A sample complex @context copied from https://json-ld.org/playground/ JSON-LD 1.1 compacted Place sample.
        /// </summary>
        private string ComplexContext1 => @"{
            ""@context"": {
            ""name"": ""http://schema.org/name"",
            ""description"": ""http://schema.org/description"",
            ""image"": {
                ""@id"": ""http://schema.org/image"",
                ""@type"": ""@id""
            },
            ""geo"": ""http://schema.org/geo"",
            ""latitude"": {
                ""@id"": ""http://schema.org/latitude"",
                ""@type"": ""xsd:float""
              },
           ""longitude"": {
                ""@id"": ""http://schema.org/longitude"",
                ""@type"": ""xsd:float""
            },
           ""xsd"": ""http://www.w3.org/2001/XMLSchema#""
           },
           ""name"": ""The Empire State Building"",
           ""description"": ""The Empire State Building is a 102-story landmark in New York City."",
           ""image"": ""http://www.civil.usherbrooke.ca/cours/gci215a/empire-state-building.jpg"",
           ""geo"": {
              ""latitude"": ""40.75"",
              ""longitude"": ""73.98""
              }
            }";

        /// <summary>
        /// A context from a ION Sidetree document.
        /// </summary>
        private string SidetreeIonContext1 => @"{
            ""@context"": [ ""https://www.w3.org/ns/did/v1"",
            {
                ""@base"": ""did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfNzJiZDE2ZDYiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiS2JfMnVOR3Nyd1VOdkh2YUNOckRGdW14VXlQTWZZd3kxNEpZZmphQUhmayIsInkiOiJhSFNDZDVEOFh0RUxvSXBpN1A5eDV1cXBpeEVxNmJDenQ0QldvUVk1UUFRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3d3dy52Y3NhdG9zaGkuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUR4SWxJak9xQk5NTGZjdzZndWpHNEdFVDM3UjBIRWM2Z20xclNZTjlMOF9RIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBLXV3TWo3RVFheURmWTRJS3pfSE9LdmJZQ05td19Tb1lhUmhOcWhFSWhudyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ0czQ1M5RFJpeU1JRVoxRl9sSjZnRVRMZWVHREwzZnpuQUViMVRGdFZXNEEifX0""
            }]
            }";



        [Fact]
        public void RoundtripServiceTest1()
        {
            var options = new JsonSerializerOptions();
            options.Converters.Add(new ServiceConverterFactory());

            Service? service = JsonSerializer.Deserialize<Service>(TestService1, options);
            Assert.NotNull(service);

            var roundTrippedJson = JsonSerializer.Serialize(service, options);
            Assert.NotNull(roundTrippedJson);

            var comparer = new JsonElementComparer();
            using var doc1 = JsonDocument.Parse(TestService1);
            using var doc2 = JsonDocument.Parse(roundTrippedJson);
            Assert.True(comparer.Equals(doc1.RootElement, doc2.RootElement));
        }


        [Fact]
        public void RoundtripOneUriContext()
        {
            var options = new JsonSerializerOptions();
            options.Converters.Add(new JsonLdContextConverter());

            Context? context = JsonSerializer.Deserialize<Context>(OneUriContext, options);
            Assert.NotNull(context);

            var roundTrippedJson = JsonSerializer.Serialize(context, options);
            Assert.NotNull(roundTrippedJson);

            var comparer = new JsonElementComparer();
            using var doc1 = JsonDocument.Parse(OneUriContext);
            using var doc2 = JsonDocument.Parse(roundTrippedJson);
            Assert.True(comparer.Equals(doc1.RootElement, doc2.RootElement));
        }


        [Fact]
        public void RoundtripCollectionUriContext()
        {
            var options = new JsonSerializerOptions();
            options.Converters.Add(new JsonLdContextConverter());

            Context? context = JsonSerializer.Deserialize<Context>(CollectionUriContext, options);
            Assert.NotNull(context);

            var roundTrippedJson = JsonSerializer.Serialize(context, options);
            Assert.NotNull(roundTrippedJson);

            var comparer = new JsonElementComparer();
            using var doc1 = JsonDocument.Parse(CollectionUriContext);
            using var doc2 = JsonDocument.Parse(roundTrippedJson);
            Assert.True(comparer.Equals(doc1.RootElement, doc2.RootElement));
        }


        [Fact]
        public void RountripComplexContext1()
        {
            var options = new JsonSerializerOptions();
            options.Converters.Add(new JsonLdContextConverter());

            Context? context = JsonSerializer.Deserialize<Context>(ComplexContext1, options);
            Assert.NotNull(context);

            var roundTrippedJson = JsonSerializer.Serialize(context, options);
            Assert.NotNull(roundTrippedJson);

            var comparer = new JsonElementComparer();
            using var doc1 = JsonDocument.Parse(ComplexContext1);
            using var doc2 = JsonDocument.Parse(roundTrippedJson);
            Assert.True(comparer.Equals(doc1.RootElement, doc2.RootElement));
        }


        [Fact]
        public void RountripSidetreeIonContest1()
        {
            var options = new JsonSerializerOptions();
            options.Converters.Add(new JsonLdContextConverter());

            Context? context = JsonSerializer.Deserialize<Context>(SidetreeIonContext1, options);
            Assert.NotNull(context);

            var roundTrippedJson = JsonSerializer.Serialize(context, options);
            Assert.NotNull(roundTrippedJson);

            var comparer = new JsonElementComparer();
            using var doc1 = JsonDocument.Parse(SidetreeIonContext1);
            using var doc2 = JsonDocument.Parse(roundTrippedJson);
            Assert.True(comparer.Equals(doc1.RootElement, doc2.RootElement));
        }
    }
}
