using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core;
using Verifiable.Core.Did;

namespace Verifiable.Tests.Core
{
    /// <summary>
    /// Tests for individual converters. The fragments are objects that contain the property under test.
    /// </summary>
    /// <remarks>
    [TestClass]
    public sealed class ConverterTests
    {
        [TestMethod]
        public void RoundtripControllerSingle()
        {
            //A fragment for a single controller instance. Either a single or multiple controller case is possible in one document.
            // lang=json, strict
            const string OriginalInputJson = @"""did:test:0x06048B83FAdaCdCB20198ABc45562Df1A3e289aF""";
            var converter = new SingleOrArrayControllerConverter();
            var controllers = GetConverted(OriginalInputJson, converter);
            Assert.AreEqual(1, controllers?.Length);

            var backConvertedJson = GetConverted(controllers, converter!);
            Assert.AreEqual(OriginalInputJson, backConvertedJson);
        }


        [TestMethod]
        public void RoundtripControllerArray()
        {
            //A fragment for an array of controller instance. Either a single or multiple controller case is possible in one document.
            const string OriginalInputJson = @"[""did:test:0x16048B83FAdaCdCB20198ABc45562Df1A3e289aF"",""did:test:0x26048B83FAdaCdCB20198ABc45562Df1A3e289aF""]";
            var converter = new SingleOrArrayControllerConverter();
            var controllers = GetConverted(OriginalInputJson, converter);
            Assert.AreEqual(2, controllers?.Length);

            var backConvertedJson = GetConverted(controllers, converter!);
            Assert.AreEqual(OriginalInputJson, backConvertedJson);
        }


        [TestMethod]
        public void RoundtripService()
        {
            //A sample test service copied from https://www.w3.org/TR/did-core/.
            const string OriginalInputJson = /*lang=json,strict*/ @"{""id"":""did:example:123456789abcdefghi#oidc"",""type"":""OpenIdConnectVersion1.0Service"",""serviceEndpoint"":""https://openid.example.com/""}";

            var factory = new ServiceConverterFactory();
            var converter = (JsonConverter<Service>)factory.CreateConverter(typeof(Service), new JsonSerializerOptions());
            
            var service = GetConverted(OriginalInputJson, converter);
            Assert.IsNotNull(service);

            var backConvertedJson = GetConverted(service, converter!);
            Assert.AreEqual(OriginalInputJson, backConvertedJson);
        }

        
        [TestMethod]
        public void RoundtripOneUriContext()
        {
            //The DID Uri from https://www.w3.org/TR/did-core/.
            // lang=json, strict
            const string OriginalInputJson = @"""https://www.w3.org/ns/did/v1""";
            var converter = new JsonLdContextConverter();

            var context = GetConverted(OriginalInputJson, converter);
            Assert.IsNotNull(context);

            var backConvertedJson = GetConverted(context, converter!);
            Assert.AreEqual(OriginalInputJson, backConvertedJson);
        }


        [TestMethod]
        public void RoundtripCollectionUriContext()
        {
            //The DID Uri from https://www.w3.org/TR/did-core/.
            const string OriginalInputJson = @"[""https://w3id.org/future-method/v1"",""https://w3id.org/veres-one/v1""]";
            var converter = new JsonLdContextConverter();

            var service = GetConverted(OriginalInputJson, converter);
            Assert.IsNotNull(service);

            var backConvertedJson = GetConverted(service, converter!);
            Assert.AreEqual(OriginalInputJson, backConvertedJson);
        }


        [TestMethod]
        public void RountripComplexContext1()
        {
            /// <summary>
            /// A sample complex @context copied from https://json-ld.org/playground/ JSON-LD 1.1 compacted Place sample.
            /// </summary>
            string OriginalInputJson = RemoveWhiteSpace(/*lang=json,strict*/ @"{
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
                }");

            var converter = new JsonLdContextConverter();

            var service = GetConverted(OriginalInputJson, converter);
            Assert.IsNotNull(service);

            var backConvertedJson = GetConverted(service, converter!);
            Assert.AreEqual(OriginalInputJson, backConvertedJson);
        }


        [TestMethod]
        public void RountripSidetreeIonContest1()
        {
            /// <summary>
            /// A sample complex @context copied from https://json-ld.org/playground/ JSON-LD 1.1 compacted Place sample.
            /// </summary>
            string OriginalInputJson = RemoveWhiteSpace(/*lang=json,strict*/ @"[ ""https://www.w3.org/ns/did/v1"",
            {
                ""@base"": ""did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfNzJiZDE2ZDYiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiS2JfMnVOR3Nyd1VOdkh2YUNOckRGdW14VXlQTWZZd3kxNEpZZmphQUhmayIsInkiOiJhSFNDZDVEOFh0RUxvSXBpN1A5eDV1cXBpeEVxNmJDenQ0QldvUVk1UUFRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3d3dy52Y3NhdG9zaGkuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUR4SWxJak9xQk5NTGZjdzZndWpHNEdFVDM3UjBIRWM2Z20xclNZTjlMOF9RIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBLXV3TWo3RVFheURmWTRJS3pfSE9LdmJZQ05td19Tb1lhUmhOcWhFSWhudyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ0czQ1M5RFJpeU1JRVoxRl9sSjZnRVRMZWVHREwzZnpuQUViMVRGdFZXNEEifX0""
            }]");

            var converter = new JsonLdContextConverter();

            var service = GetConverted(OriginalInputJson, converter);
            Assert.IsNotNull(service);

            var backConvertedJson = GetConverted(service, converter!);
            Assert.AreEqual(OriginalInputJson, backConvertedJson);
        }


        /// <summary>
        /// Removes whitespace from the string: start, end, in between.
        /// </summary>
        /// <param name="str">The string from which to remove whitespace.</param>
        /// <returns>The input <paramref name="str"/> without whitespace.</returns>
        private static string RemoveWhiteSpace(string str)
        {
            return string.Concat(str.Where(c => !char.IsWhiteSpace(c)));
        }


        /// <summary>
        /// Tries to convert the input JSON to a strongly typed object using the given converter.
        /// </summary>
        /// <typeparam name="TConversionTarget">The conversion target type.</typeparam>
        /// <param name="json">The JSON to try to convert.</param>
        /// <param name="converter">The converter to use.</param>
        /// <returns>An instace of the given target type if conversion succeeded.</returns>
        private static TConversionTarget? GetConverted<TConversionTarget>(string json, JsonConverter<TConversionTarget> converter) where TConversionTarget: class
        {
            var utf8JsonReader = new Utf8JsonReader(Encoding.UTF8.GetBytes(json));
            var options = new JsonSerializerOptions();

            Assert.AreEqual(JsonTokenType.None, utf8JsonReader.TokenType);
            _ = utf8JsonReader.Read();

            return converter.Read(ref utf8JsonReader, typeof(TConversionTarget), options);
        }


        /// <summary>
        /// Tries to convert the input type to json using the given converter.
        /// </summary>
        /// <typeparam name="TInput">The input type.</typeparam>
        /// <param name="input">The input object.</param>
        /// <param name="converter">The converter to use.</param>
        /// <returns>JSON representation of the given target type if conversion succeeded.</returns>
        private static string? GetConverted<TInput>(TInput input, JsonConverter<TInput> converter)
        {
            using(var stream = new MemoryStream())
            {
                using(var writer = new Utf8JsonWriter(stream))
                {
                    converter.Write(writer, input!, new JsonSerializerOptions());
                }

                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }
    }
}
